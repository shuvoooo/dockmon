#!/usr/bin/env python3
"""
dockmon — single-file Docker container monitoring dashboard.

Zero pip dependencies (stdlib only). Talks to the Docker Engine API
over /var/run/docker.sock and serves a live dashboard with full
observability: CPU/memory gauges, sparklines, network I/O, disk I/O,
container health, uptime, restart counts, port bindings, logs, events.

Run:
    sudo python3 dockmon.py            # http://0.0.0.0:8090
    sudo python3 dockmon.py --port 9000 --bind 127.0.0.1
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DOCKER_SOCK = "/var/run/docker.sock"
API_VERSION = "v1.44"   # minimum supported by recent Docker Engine

# Set by main() from CLI args or DOCKMON_USER / DOCKMON_PASSWORD env vars.
# Stored as a constant-time-comparable digest so the plaintext never sits in RAM.
_AUTH_TOKEN: str | None = None   # base64("user:pass") exactly as the client sends


def _set_auth(user: str, password: str) -> None:
    global _AUTH_TOKEN
    raw = f"{user}:{password}"
    _AUTH_TOKEN = base64.b64encode(raw.encode()).decode()


def _check_auth(handler: "Handler") -> bool:
    """Return True if the request is authorised (or auth is disabled)."""
    if _AUTH_TOKEN is None:
        return True
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    provided = header[len("Basic "):]
    # constant-time comparison to resist timing attacks
    return hashlib.sha256(provided.encode()).digest() == hashlib.sha256(_AUTH_TOKEN.encode()).digest()

# ---------------------------------------------------------------------------
# Docker Engine API over the unix socket (stdlib only)
# ---------------------------------------------------------------------------

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self.sock_path = sock_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.sock_path)
        self.sock = s


def _docker_request(method, path, timeout=10):
    conn = UnixHTTPConnection(DOCKER_SOCK, timeout=timeout)
    try:
        conn.request(method, f"/{API_VERSION}{path}")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status >= 400:
            raise RuntimeError(f"Docker API {resp.status}: {body[:300]!r}")
        return resp.status, body
    finally:
        conn.close()


def docker_get(path, timeout=10):
    _, body = _docker_request("GET", path, timeout=timeout)
    return json.loads(body)


def docker_get_text(path, timeout=10):
    _, body = _docker_request("GET", path, timeout=timeout)
    return body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Stats collection
# ---------------------------------------------------------------------------

_prev_io: dict = {}
_prev_io_lock = threading.Lock()

# circular event buffer
_events: list = []
_events_lock = threading.Lock()
_events_max = 200


def _calc_cpu_percent(stats):
    try:
        cpu = stats["cpu_stats"]
        pre = stats["precpu_stats"]
        cpu_delta = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpus = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or []) or 1
        if cpu_delta > 0 and sys_delta > 0:
            return (cpu_delta / sys_delta) * ncpus * 100.0
    except (KeyError, TypeError):
        pass
    return 0.0


def _calc_mem(stats):
    try:
        m = stats["memory_stats"]
        usage = m.get("usage", 0)
        s = m.get("stats", {}) or {}
        cache = s.get("inactive_file", s.get("total_inactive_file", s.get("cache", 0))) or 0
        usage = max(usage - cache, 0)
        limit = m.get("limit", 0)
        pct = (usage / limit * 100.0) if limit else 0.0
        return usage, limit, round(pct, 2)
    except (KeyError, TypeError):
        return 0, 0, 0.0


def _calc_net(stats):
    rx = tx = 0
    for iface in (stats.get("networks") or {}).values():
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    return rx, tx


def _calc_blk(stats):
    br = bw = 0
    for entry in (stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []):
        op = entry.get("op", "").lower()
        if op == "read":
            br += entry.get("value", 0)
        elif op == "write":
            bw += entry.get("value", 0)
    return br, bw


def _fmt_ports(ports):
    """Format port bindings list from /containers/json into readable strings."""
    out = []
    seen = set()
    for p in (ports or []):
        pub = p.get("PublicPort")
        priv = p.get("PrivatePort")
        proto = p.get("Type", "tcp")
        key = (pub, priv, proto)
        if key in seen:
            continue
        seen.add(key)
        if pub:
            out.append(f"{pub}→{priv}/{proto}")
        else:
            out.append(f"{priv}/{proto}")
    return ", ".join(out[:6])  # cap at 6 to avoid huge rows


def _fetch_one(c):
    cid = c["Id"]
    name = (c.get("Names") or ["/?"])[0].lstrip("/")

    # health from /containers/json Status field (e.g. "Up 2 hours (healthy)")
    raw_status = c.get("Status", "")
    health = "none"
    if "(healthy)" in raw_status:
        health = "healthy"
    elif "(unhealthy)" in raw_status:
        health = "unhealthy"
    elif "(health:" in raw_status:
        health = "starting"

    base = {
        "id": cid[:12],
        "full_id": cid,
        "name": name,
        "image": c.get("Image", ""),
        "state": c.get("State", ""),
        "status": raw_status,
        "health": health,
        "created": c.get("Created", 0),
        "ports": _fmt_ports(c.get("Ports")),
        "cpu": 0.0,
        "mem_used": 0, "mem_limit": 0, "mem_pct": 0.0,
        "net_rx": 0, "net_tx": 0, "net_rx_rate": 0.0, "net_tx_rate": 0.0,
        "blk_r": 0, "blk_w": 0, "blk_r_rate": 0.0, "blk_w_rate": 0.0,
        "pids": 0,
        "restart_count": 0,
        "uptime_s": 0,
    }

    if c.get("State") != "running":
        return base

    # fetch detailed inspect for restart_count (cheap)
    try:
        detail = docker_get(f"/containers/{cid}/json", timeout=4)
        base["restart_count"] = (detail.get("RestartCount") or 0)
        started_at = detail.get("State", {}).get("StartedAt", "")
        if started_at:
            # parse ISO8601 timestamp (Python 3.11+ fromisoformat handles Z,
            # but for 3.9/3.10 we strip trailing nanoseconds manually)
            try:
                import datetime
                ts = started_at[:19]  # "2024-01-02T15:04:05"
                dt = datetime.datetime.fromisoformat(ts)
                base["uptime_s"] = int(time.time() - dt.replace(tzinfo=datetime.timezone.utc).timestamp())
            except Exception:
                pass
    except Exception:
        pass

    try:
        stats = docker_get(f"/containers/{cid}/stats?stream=false&one-shot=true", timeout=8)
    except Exception:
        return base

    base["cpu"] = round(_calc_cpu_percent(stats), 2)
    used, limit, pct = _calc_mem(stats)
    base["mem_used"], base["mem_limit"], base["mem_pct"] = used, limit, pct
    rx, tx = _calc_net(stats)
    br, bw = _calc_blk(stats)
    base["net_rx"], base["net_tx"] = rx, tx
    base["blk_r"], base["blk_w"] = br, bw
    base["pids"] = (stats.get("pids_stats") or {}).get("current", 0)

    now = time.time()
    with _prev_io_lock:
        prev = _prev_io.get(cid)
        _prev_io[cid] = {"t": now, "rx": rx, "tx": tx, "br": br, "bw": bw}
    if prev and now > prev["t"]:
        dt = now - prev["t"]
        base["net_rx_rate"] = round(max(rx - prev["rx"], 0) / dt, 1)
        base["net_tx_rate"] = round(max(tx - prev["tx"], 0) / dt, 1)
        base["blk_r_rate"] = round(max(br - prev["br"], 0) / dt, 1)
        base["blk_w_rate"] = round(max(bw - prev["bw"], 0) / dt, 1)

    return base


def collect_stats():
    containers = docker_get("/containers/json?all=1")
    with ThreadPoolExecutor(max_workers=min(20, max(4, len(containers) or 1))) as ex:
        futs = [ex.submit(_fetch_one, c) for c in containers]
        results = [f.result() for f in as_completed(futs)]

    alive = {c["Id"] for c in containers}
    with _prev_io_lock:
        for k in list(_prev_io):
            if k not in alive:
                del _prev_io[k]

    info = {}
    try:
        raw = docker_get("/info")
        info = {
            "host": raw.get("Name", ""),
            "ncpu": raw.get("NCPU", 0),
            "mem_total": raw.get("MemTotal", 0),
            "docker_version": raw.get("ServerVersion", ""),
            "os": raw.get("OperatingSystem", ""),
            "kernel": raw.get("KernelVersion", ""),
            "containers_running": raw.get("ContainersRunning", 0),
            "containers_paused": raw.get("ContainersPaused", 0),
            "containers_stopped": raw.get("ContainersStopped", 0),
            "images": raw.get("Images", 0),
        }
    except Exception:
        pass

    return {"ts": time.time(), "host": info, "containers": results}


def get_container_logs(cid, tail=100, since=0):
    path = f"/containers/{cid}/logs?stdout=1&stderr=1&tail={tail}&timestamps=1"
    if since:
        path += f"&since={since}"
    try:
        raw = docker_get_text(path, timeout=10)
        # Docker multiplexes log streams with 8-byte headers; strip them
        lines = []
        data = raw.encode("utf-8", errors="replace")
        i = 0
        while i < len(data):
            if i + 8 > len(data):
                break
            size = int.from_bytes(data[i+4:i+8], "big")
            chunk = data[i+8:i+8+size].decode("utf-8", errors="replace")
            lines.append(chunk)
            i += 8 + size
        return "".join(lines) if lines else raw
    except Exception as e:
        return f"[log error: {e}]"


def get_recent_events(limit=50):
    with _events_lock:
        return list(_events[-limit:])


def _event_watcher():
    """Background thread: tails Docker events and stores in ring buffer."""
    while True:
        try:
            conn = UnixHTTPConnection(DOCKER_SOCK, timeout=None)
            conn.request("GET", f"/{API_VERSION}/events")
            resp = conn.getresponse()
            while True:
                line = resp.readline()
                if not line:
                    break
                try:
                    ev = json.loads(line)
                    entry = {
                        "time": ev.get("time", int(time.time())),
                        "type": ev.get("Type", ""),
                        "action": ev.get("Action", ""),
                        "actor": (ev.get("Actor") or {}).get("Attributes", {}).get("name", ""),
                        "id": (ev.get("id") or "")[:12],
                    }
                    with _events_lock:
                        _events.append(entry)
                        if len(_events) > _events_max:
                            _events.pop(0)
                except Exception:
                    pass
        except Exception:
            time.sleep(5)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "dockmon/2.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _require_auth(self) -> bool:
        """Send 401 and return False if the request is not authorised."""
        if _check_auth(self):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="dockmon"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "12")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"Unauthorized")
        return False

    def do_GET(self):
        if not self._require_auth():
            return

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        try:
            if path == "/api/stats":
                self._json(200, collect_stats())

            elif path == "/api/events":
                self._json(200, {"events": get_recent_events()})

            elif path.startswith("/api/logs/"):
                cid = path[len("/api/logs/"):]
                tail = int(qs.get("tail", ["100"])[0])
                logs = get_container_logs(cid, tail=tail)
                self._send(200, logs, "text/plain; charset=utf-8")

            elif path.startswith("/api/inspect/"):
                cid = path[len("/api/inspect/"):]
                detail = docker_get(f"/containers/{cid}/json", timeout=6)
                self._json(200, detail)

            elif path == "/" or path.startswith("/index"):
                self._send(200, PAGE, "text/html; charset=utf-8")

            else:
                self._send(404, "not found", "text/plain")

        except FileNotFoundError:
            self._json(500, {"error": f"Cannot reach {DOCKER_SOCK}. Is Docker running?"})
        except PermissionError:
            self._json(500, {"error": f"Permission denied on {DOCKER_SOCK}. Run with sudo."})
        except Exception as e:
            self._json(500, {"error": str(e)})


# ---------------------------------------------------------------------------
# Frontend — embedded single-page app
# ---------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dockmon</title>
<style>
:root{
  --bg:#0d1117;--panel:#161b22;--panel2:#1c2333;--line:#21262d;
  --text:#e6edf3;--dim:#8b949e;--faint:#484f58;
  --copper:#f0883e;--copper-dim:#9e5f25;
  --ok:#3fb950;--warn:#d29922;--hot:#f85149;--blue:#58a6ff;--purple:#bc8cff;
  --mono:'JetBrains Mono','Cascadia Mono','SF Mono',ui-monospace,Menlo,Consolas,monospace;
  --sans:'Segoe UI',system-ui,-apple-system,sans-serif;
  --r:6px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;height:100%}
a{color:var(--copper);text-decoration:none}

/* ── layout ── */
#app{display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;
  padding:14px 20px;border-bottom:1px solid var(--line);background:var(--panel);flex-shrink:0}
header h1{font-family:var(--mono);font-size:16px;font-weight:700;letter-spacing:.05em;color:var(--copper);white-space:nowrap}
header h1 .dot{color:var(--ok)}
#hostline{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
#err{font-family:var(--mono);font-size:11.5px;color:var(--hot)}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:10px}
#ts{font-family:var(--mono);font-size:10px;color:var(--faint)}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:blink 1.5s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* ── system cards ── */
.sysbar{display:flex;gap:12px;flex-wrap:wrap;padding:14px 20px;
  border-bottom:1px solid var(--line);background:var(--panel);flex-shrink:0;overflow-x:auto}
.scard{background:var(--panel2);border:1px solid var(--line);border-radius:var(--r);
  padding:10px 16px;min-width:130px;flex-shrink:0}
.scard .sv{font-family:var(--mono);font-size:20px;font-weight:600;color:var(--text)}
.scard .sv .u{font-size:12px;color:var(--dim);font-weight:400}
.scard .sk{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-top:4px}
.scard .sbar{height:3px;background:var(--line);border-radius:2px;margin-top:8px}
.scard .sbar i{display:block;height:100%;border-radius:2px;background:var(--ok);transition:width .5s}
.scard .sbar i.warn{background:var(--warn)} .scard .sbar i.hot{background:var(--hot)}

/* ── tabs ── */
.tabs{display:flex;gap:2px;padding:10px 20px 0;border-bottom:1px solid var(--line);
  background:var(--panel);flex-shrink:0}
.tab{font-family:var(--mono);font-size:12px;color:var(--dim);padding:7px 14px;
  border-radius:var(--r) var(--r) 0 0;cursor:pointer;border:1px solid transparent;border-bottom:none;
  transition:color .15s,background .15s}
.tab:hover{color:var(--text);background:var(--panel2)}
.tab.on{color:var(--copper);background:var(--bg);border-color:var(--line)}
.tabcount{display:inline-block;background:var(--panel2);border-radius:10px;
  font-size:10px;padding:1px 6px;margin-left:5px;color:var(--faint)}
.tab.on .tabcount{background:var(--copper-dim);color:var(--text)}

/* ── tab panels ── */
.tpanel{flex:1;overflow:auto;padding:16px 20px}
.tpanel[hidden]{display:none}

/* ── controls ── */
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.controls input[type=text]{background:var(--panel);border:1px solid var(--line);color:var(--text);
  font-family:var(--mono);font-size:12px;padding:7px 10px;border-radius:var(--r);
  width:240px;outline:none;transition:border-color .15s}
.controls input[type=text]:focus{border-color:var(--copper-dim)}
.seg{display:flex;border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
.seg button{background:var(--panel);border:0;color:var(--dim);font-family:var(--mono);
  font-size:11.5px;padding:7px 11px;cursor:pointer;transition:background .15s,color .15s}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:var(--panel2);color:var(--copper)}
select{background:var(--panel);border:1px solid var(--line);color:var(--text);
  font-family:var(--mono);font-size:12px;padding:6px 8px;border-radius:var(--r)}
.clabel{font-family:var(--mono);font-size:10.5px;color:var(--faint);letter-spacing:.08em;text-transform:uppercase}
#count{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--faint)}

/* ── table ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
thead th{position:sticky;top:0;background:var(--bg);z-index:2;
  text-align:left;font-weight:500;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--faint);padding:8px 10px;border-bottom:1px solid var(--line);
  cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:var(--dim)}
thead th.sorted{color:var(--copper)}
thead th .arr{font-size:8px;margin-left:3px}
tbody td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
tbody tr:hover{background:var(--panel)}
tbody tr.selected{background:#1c2333}
td.name{color:var(--text);font-weight:600;max-width:200px;overflow:hidden;text-overflow:ellipsis}
td.img{color:var(--dim);max-width:180px;overflow:hidden;text-overflow:ellipsis}
td.id{color:var(--faint)}
td.ports{color:var(--purple);max-width:180px;overflow:hidden;text-overflow:ellipsis}

.badge{display:inline-block;font-size:10px;padding:2px 7px;border-radius:3px;letter-spacing:.04em;font-weight:500}
.badge.running{color:var(--ok);background:rgba(63,185,80,.12)}
.badge.exited,.badge.dead{color:var(--faint);background:rgba(72,79,88,.2)}
.badge.paused{color:var(--warn);background:rgba(210,153,34,.12)}
.badge.restarting{color:var(--hot);background:rgba(248,81,73,.12)}
.badge.created{color:var(--blue);background:rgba(88,166,255,.12)}

.hbadge{display:inline-block;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:4px}
.hbadge.healthy{color:var(--ok);background:rgba(63,185,80,.12)}
.hbadge.unhealthy{color:var(--hot);background:rgba(248,81,73,.12)}
.hbadge.starting{color:var(--warn);background:rgba(210,153,34,.12)}

.gauge{display:flex;align-items:center;gap:7px;min-width:140px}
.gauge .num{width:58px;text-align:right}
.bar{flex:1;height:4px;background:var(--panel2);border-radius:2px;overflow:hidden;min-width:55px}
.bar i{display:block;height:100%;border-radius:2px;background:var(--ok);transition:width .5s}
.bar i.warn{background:var(--warn)} .bar i.hot{background:var(--hot)}
.sub{color:var(--faint);font-size:11px}
canvas.spark{display:block;width:80px;height:20px;vertical-align:middle}
.rate{color:var(--blue)}
.restarts{color:var(--hot)}
.uptime{color:var(--dim)}
.empty{padding:60px;text-align:center;color:var(--faint);font-family:var(--mono)}
.act-btn{background:var(--panel2);border:1px solid var(--line);color:var(--dim);
  font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:3px;cursor:pointer}
.act-btn:hover{color:var(--text);border-color:var(--dim)}

/* ── logs panel ── */
#logPanel{display:flex;flex-direction:column;height:100%}
#logHeader{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-shrink:0}
#logTitle{font-family:var(--mono);font-size:13px;color:var(--copper);font-weight:600}
#logBody{flex:1;overflow-y:auto;background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r);padding:12px;font-family:var(--mono);font-size:11.5px;
  color:var(--text);white-space:pre-wrap;word-break:break-all;line-height:1.6}
#logBody .err{color:var(--hot)} #logBody .ts{color:var(--faint)}

/* ── events panel ── */
#evTable{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
#evTable td{padding:6px 10px;border-bottom:1px solid var(--line)}
#evTable td:first-child{color:var(--faint);width:90px}
#evTable .ev-action{color:var(--blue);width:100px}
#evTable .ev-type{color:var(--purple);width:80px}
#evTable .ev-name{color:var(--text);font-weight:500}

/* ── inspect panel ── */
#inspectPanel{height:100%;display:flex;flex-direction:column}
#inspectTitle{font-family:var(--mono);font-size:13px;color:var(--copper);font-weight:600;margin-bottom:10px;flex-shrink:0}
#inspectBody{flex:1;overflow:auto;background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r);padding:12px;font-family:var(--mono);font-size:11.5px;
  color:var(--text);white-space:pre;line-height:1.5}

@media(max-width:700px){.controls input[type=text]{width:100%}}
@media(prefers-reduced-motion:reduce){.bar i,.pulse{animation:none;transition:none}}
</style>
</head>
<body>
<div id="app">

<header>
  <h1><span class="dot">●</span> dockmon</h1>
  <span id="hostline">connecting…</span>
  <span id="err"></span>
  <div class="hdr-right">
    <span id="ts"></span>
    <div class="pulse" id="pulse" style="display:none"></div>
    <select id="iv">
      <option value="2000">refresh 2s</option>
      <option value="5000" selected>refresh 5s</option>
      <option value="10000">refresh 10s</option>
      <option value="30000">refresh 30s</option>
      <option value="0">paused</option>
    </select>
  </div>
</header>

<div class="sysbar">
  <div class="scard"><div class="sv" id="sc-run">–</div><div class="sk">containers running</div></div>
  <div class="scard"><div class="sv" id="sc-total">–</div><div class="sk">total containers</div></div>
  <div class="scard"><div class="sv" id="sc-images">–</div><div class="sk">images</div></div>
  <div class="scard">
    <div class="sv" id="sc-cpu">–</div><div class="sk">Σ CPU</div>
    <div class="sbar"><i id="sc-cpu-bar"></i></div>
  </div>
  <div class="scard">
    <div class="sv" id="sc-mem">–</div><div class="sk">Σ memory used</div>
    <div class="sbar"><i id="sc-mem-bar"></i></div>
  </div>
  <div class="scard"><div class="sv" id="sc-netrx">–</div><div class="sk">Σ net rx/s</div></div>
  <div class="scard"><div class="sv" id="sc-nettx">–</div><div class="sk">Σ net tx/s</div></div>
  <div class="scard"><div class="sv" id="sc-blkr">–</div><div class="sk">Σ disk r/s</div></div>
  <div class="scard"><div class="sv" id="sc-blkw">–</div><div class="sk">Σ disk w/s</div></div>
</div>

<div class="tabs">
  <div class="tab on" data-t="containers">Containers<span class="tabcount" id="tc-cont">0</span></div>
  <div class="tab" data-t="events">Events<span class="tabcount" id="tc-ev">0</span></div>
  <div class="tab" data-t="logs" id="tabLogs" style="display:none">Logs</div>
  <div class="tab" data-t="inspect" id="tabInspect" style="display:none">Inspect</div>
</div>

<!-- containers tab -->
<div class="tpanel" id="panel-containers">
  <div class="controls">
    <input id="q" type="text" placeholder="filter name / image / id…" autocomplete="off">
    <div class="seg" id="stateSeg">
      <button data-s="all" class="on">all</button>
      <button data-s="running">running</button>
      <button data-s="exited">exited</button>
      <button data-s="paused">paused</button>
    </div>
    <span id="count"></span>
  </div>
  <div class="tbl-wrap">
  <table>
    <thead><tr>
      <th data-k="name">Name<span class="arr"></span></th>
      <th data-k="state">State<span class="arr"></span></th>
      <th data-k="cpu">CPU %<span class="arr"></span></th>
      <th>CPU trend</th>
      <th data-k="mem_pct">Memory<span class="arr"></span></th>
      <th>Mem trend</th>
      <th data-k="net_rx_rate">Net RX/s<span class="arr"></span></th>
      <th data-k="net_tx_rate">Net TX/s<span class="arr"></span></th>
      <th data-k="blk_r_rate">Disk R/s<span class="arr"></span></th>
      <th data-k="blk_w_rate">Disk W/s<span class="arr"></span></th>
      <th data-k="pids">PIDs<span class="arr"></span></th>
      <th data-k="restart_count">Restarts<span class="arr"></span></th>
      <th data-k="uptime_s">Uptime<span class="arr"></span></th>
      <th data-k="ports">Ports<span class="arr"></span></th>
      <th data-k="image">Image<span class="arr"></span></th>
      <th data-k="id">ID<span class="arr"></span></th>
      <th>Actions</th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <div class="empty" id="empty" hidden>No containers match.</div>
  </div>
</div>

<!-- events tab -->
<div class="tpanel" id="panel-events" hidden>
  <div class="controls">
    <input id="evq" type="text" placeholder="filter events…" autocomplete="off">
    <span id="ecount" style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--faint)"></span>
  </div>
  <div class="tbl-wrap">
  <table id="evTable">
    <thead><tr><th>Time</th><th>Type</th><th>Action</th><th>Container</th><th>ID</th></tr></thead>
    <tbody id="evRows"></tbody>
  </table>
  <div class="empty" id="evEmpty" hidden>No events yet.</div>
  </div>
</div>

<!-- logs tab -->
<div class="tpanel" id="panel-logs" hidden>
  <div id="logPanel">
    <div id="logHeader">
      <span id="logTitle">Logs</span>
      <select id="logTail">
        <option value="50">last 50 lines</option>
        <option value="100" selected>last 100 lines</option>
        <option value="200">last 200 lines</option>
        <option value="500">last 500 lines</option>
      </select>
      <button class="act-btn" onclick="reloadLogs()">↺ Reload</button>
      <button class="act-btn" id="logAutoBtn" onclick="toggleLogAuto()">Auto ●</button>
    </div>
    <pre id="logBody">Select a container and click Logs.</pre>
  </div>
</div>

<!-- inspect tab -->
<div class="tpanel" id="panel-inspect" hidden>
  <div id="inspectPanel">
    <div id="inspectTitle">Inspect</div>
    <pre id="inspectBody">Select a container and click Inspect.</pre>
  </div>
</div>

</div><!-- #app -->

<script>
"use strict";
const HIST_LEN = 50;
let DATA=[], HIST={}, MEM_HIST={}, EVENTS=[];
let sortKey="cpu", sortDir=-1, stateFilter="all", timer=null;
let activeTab="containers", logCid=null, logAutoTimer=null, logAutoOn=false;

const fmtB = n=>{
  if(!n||n<0) return "0 B";
  const u=["B","KB","MB","GB","TB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (n>=100?n.toFixed(0):n.toFixed(1))+" "+u[i];
};
const fmtUptime = s=>{
  if(!s) return "";
  if(s<60) return s+"s";
  if(s<3600) return Math.floor(s/60)+"m "+Math.floor(s%60)+"s";
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);
  if(h<24) return h+"h "+m+"m";
  return Math.floor(h/24)+"d "+Math.floor(h%24)+"h";
};
const fmtTime = ts=>{
  const d=new Date(ts*1000);
  return d.toLocaleTimeString();
};
const esc = s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const colorCls=(v,w,h)=>v>h?"hot":v>w?"warn":"";

// ── fetch stats ──────────────────────────────────────────────────────────────
async function poll(){
  try{
    const r=await fetch("/api/stats");
    const j=await r.json();
    if(j.error) throw new Error(j.error);
    document.getElementById("err").textContent="";
    document.getElementById("pulse").style.display="block";
    DATA=j.containers||[];
    const h=j.host||{};
    document.getElementById("hostline").textContent=[
      h.host&&("host: "+h.host),
      h.docker_version&&("docker "+h.docker_version),
      h.os,
      h.kernel&&("kernel "+h.kernel),
    ].filter(Boolean).join("  ·  ");
    document.getElementById("ts").textContent=new Date().toLocaleTimeString();

    // history
    for(const c of DATA){
      if(c.state!=="running") continue;
      const id=c.id;
      (HIST[id]=HIST[id]||[]).push(c.cpu);
      if(HIST[id].length>HIST_LEN) HIST[id].shift();
      (MEM_HIST[id]=MEM_HIST[id]||[]).push(c.mem_pct);
      if(MEM_HIST[id].length>HIST_LEN) MEM_HIST[id].shift();
    }

    // system cards
    const running=DATA.filter(c=>c.state==="running");
    const cpuSum=running.reduce((s,c)=>s+c.cpu,0);
    const memUsed=running.reduce((s,c)=>s+c.mem_used,0);
    const memLimit=running.reduce((s,c)=>s+c.mem_limit,0);
    const memPct=memLimit?memUsed/memLimit*100:0;
    const totalCPU=(h.ncpu||1)*100;
    const cpuPct=Math.min(cpuSum/totalCPU*100,100);

    document.getElementById("sc-run").textContent=h.containers_running??running.length;
    document.getElementById("sc-total").textContent=DATA.length;
    document.getElementById("sc-images").textContent=h.images??"-";
    document.getElementById("sc-cpu").innerHTML=cpuSum.toFixed(1)+'<span class="u"> %</span>';
    document.getElementById("sc-cpu-bar").style.width=cpuPct.toFixed(1)+"%";
    document.getElementById("sc-cpu-bar").className=colorCls(cpuPct,50,85);
    document.getElementById("sc-mem").textContent=fmtB(memUsed);
    document.getElementById("sc-mem-bar").style.width=memPct.toFixed(1)+"%";
    document.getElementById("sc-mem-bar").className=colorCls(memPct,60,85);
    document.getElementById("sc-netrx").textContent=fmtB(running.reduce((s,c)=>s+c.net_rx_rate,0))+"/s";
    document.getElementById("sc-nettx").textContent=fmtB(running.reduce((s,c)=>s+c.net_tx_rate,0))+"/s";
    document.getElementById("sc-blkr").textContent=fmtB(running.reduce((s,c)=>s+c.blk_r_rate,0))+"/s";
    document.getElementById("sc-blkw").textContent=fmtB(running.reduce((s,c)=>s+c.blk_w_rate,0))+"/s";

    document.getElementById("tc-cont").textContent=DATA.length;
    render();
  } catch(e){
    document.getElementById("err").textContent="⚠ "+e.message;
    document.getElementById("pulse").style.display="none";
  }
}

async function pollEvents(){
  try{
    const r=await fetch("/api/events");
    const j=await r.json();
    EVENTS=(j.events||[]).reverse();
    document.getElementById("tc-ev").textContent=EVENTS.length;
    if(activeTab==="events") renderEvents();
  } catch(e){}
}

// ── render containers ────────────────────────────────────────────────────────
function render(){
  const q=document.getElementById("q").value.trim().toLowerCase();
  let rows=DATA.filter(c=>
    (stateFilter==="all"||c.state===stateFilter)&&
    (!q||c.name.toLowerCase().includes(q)||c.image.toLowerCase().includes(q)||c.id.includes(q))
  );
  rows.sort((a,b)=>{
    const x=a[sortKey],y=b[sortKey];
    const r=(typeof x==="string")?x.localeCompare(y):(x-y);
    return r*sortDir;
  });
  document.getElementById("count").textContent=rows.length+" shown";
  document.getElementById("empty").hidden=rows.length>0;

  const tb=document.getElementById("rows");
  tb.innerHTML=rows.map(c=>{
    const run=c.state==="running";
    const cpuCls=colorCls(c.cpu,50,85);
    const memCls=colorCls(c.mem_pct,60,85);
    const healthBadge=c.health!=="none"?`<span class="hbadge ${esc(c.health)}">${esc(c.health)}</span>`:"";
    return `<tr data-cid="${esc(c.full_id||c.id)}">
      <td class="name" title="${esc(c.name)}">${esc(c.name)}</td>
      <td><span class="badge ${esc(c.state)}">${esc(c.state)}</span>${healthBadge}</td>
      <td>${run?`<div class="gauge"><span class="num ${cpuCls?'':''}">
        ${c.cpu.toFixed(1)}%</span><span class="bar"><i class="${cpuCls}" style="width:${Math.min(c.cpu,100)}%"></i></span></div>`:'<span class="sub">—</span>'}</td>
      <td>${run?`<canvas class="spark" data-id="${esc(c.id)}" data-hist="cpu" width="160" height="40"></canvas>`:""}</td>
      <td>${run?`<div class="gauge"><span class="num">${c.mem_pct.toFixed(1)}%</span>
        <span class="bar"><i class="${memCls}" style="width:${Math.min(c.mem_pct,100)}%"></i></span>
        <span class="sub" style="margin-left:4px">${fmtB(c.mem_used)}</span></div>`:'<span class="sub">—</span>'}</td>
      <td>${run?`<canvas class="spark" data-id="${esc(c.id)}" data-hist="mem" width="160" height="40"></canvas>`:""}</td>
      <td class="rate">${run?fmtB(c.net_rx_rate)+"/s":""}</td>
      <td class="rate">${run?fmtB(c.net_tx_rate)+"/s":""}</td>
      <td class="sub">${run?fmtB(c.blk_r_rate)+"/s":""}</td>
      <td class="sub">${run?fmtB(c.blk_w_rate)+"/s":""}</td>
      <td class="sub">${run?c.pids:""}</td>
      <td class="${c.restart_count>0?"restarts":"sub"}">${c.restart_count>0?c.restart_count:""}</td>
      <td class="uptime">${run?fmtUptime(c.uptime_s):""}</td>
      <td class="ports" title="${esc(c.ports)}">${esc(c.ports)}</td>
      <td class="img" title="${esc(c.image)}">${esc(c.image)}</td>
      <td class="id">${esc(c.id)}</td>
      <td><button class="act-btn" onclick="openLogs('${esc(c.full_id||c.id)}','${esc(c.name)}')">Logs</button>
          <button class="act-btn" onclick="openInspect('${esc(c.full_id||c.id)}','${esc(c.name)}')">Inspect</button></td>
    </tr>`;
  }).join("");

  document.querySelectorAll("canvas.spark").forEach(cv=>{
    const hist=cv.dataset.hist==="mem"?MEM_HIST:HIST;
    const h=hist[cv.dataset.id]||[];
    drawSpark(cv,h,cv.dataset.hist==="mem"?"#bc8cff":"#f0883e");
  });

  document.querySelectorAll("thead th[data-k]").forEach(th=>{
    const on=th.dataset.k===sortKey;
    th.classList.toggle("sorted",on);
    th.querySelector(".arr").textContent=on?(sortDir===-1?"▼":"▲"):"";
  });
}

function drawSpark(cv,h,color){
  const ctx=cv.getContext("2d");
  ctx.clearRect(0,0,cv.width,cv.height);
  if(h.length<2) return;
  const max=Math.max(10,...h),W=cv.width,H=cv.height,step=W/(HIST_LEN-1);
  // fill
  ctx.beginPath();
  h.forEach((v,i)=>{
    const x=W-(h.length-1-i)*step,y=H-2-(v/max)*(H-6);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.lineTo(W-(0)*step,H); ctx.lineTo(W-(h.length-1)*step,H);
  ctx.closePath();
  ctx.fillStyle=color+"22"; ctx.fill();
  // line
  ctx.beginPath();
  h.forEach((v,i)=>{
    const x=W-(h.length-1-i)*step,y=H-2-(v/max)*(H-6);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.strokeStyle=color; ctx.lineWidth=1.5; ctx.stroke();
}

// ── render events ─────────────────────────────────────────────────────────────
function renderEvents(){
  const q=document.getElementById("evq").value.trim().toLowerCase();
  const rows=EVENTS.filter(e=>!q||JSON.stringify(e).toLowerCase().includes(q));
  document.getElementById("ecount").textContent=rows.length+" events";
  document.getElementById("evEmpty").hidden=rows.length>0;
  const actionColor={start:"#3fb950",stop:"#f85149",die:"#f85149",kill:"#f85149",
    pause:"#d29922",unpause:"#3fb950",restart:"#58a6ff",create:"#bc8cff",destroy:"#484f58"};
  document.getElementById("evRows").innerHTML=rows.map(e=>{
    const ac=actionColor[e.action]||"#8b949e";
    return `<tr>
      <td>${fmtTime(e.time)}</td>
      <td class="ev-type">${esc(e.type)}</td>
      <td class="ev-action" style="color:${ac}">${esc(e.action)}</td>
      <td class="ev-name">${esc(e.actor)}</td>
      <td class="id">${esc(e.id)}</td>
    </tr>`;
  }).join("");
}

// ── logs ───────────────────────────────────────────────────────────────────
async function openLogs(cid,name){
  logCid=cid;
  document.getElementById("tabLogs").textContent="Logs: "+name;
  document.getElementById("tabLogs").style.display="";
  document.getElementById("logTitle").textContent="Logs — "+name;
  switchTab("logs");
  await reloadLogs();
}
async function reloadLogs(){
  if(!logCid) return;
  const tail=document.getElementById("logTail").value;
  document.getElementById("logBody").textContent="Loading…";
  try{
    const r=await fetch("/api/logs/"+logCid+"?tail="+tail);
    const txt=await r.text();
    const body=document.getElementById("logBody");
    body.innerHTML=txt.split("\n").map(l=>{
      const isErr=/\b(err|error|fail|fatal|warn|warning)\b/i.test(l);
      const ts=l.match(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z/);
      if(ts) l='<span class="ts">'+esc(ts[0])+'</span>'+esc(l.slice(ts[0].length));
      else l=esc(l);
      return isErr?`<span class="err">${l}</span>`:l;
    }).join("\n");
    body.scrollTop=body.scrollHeight;
  } catch(e){
    document.getElementById("logBody").textContent="Error: "+e.message;
  }
}
function toggleLogAuto(){
  logAutoOn=!logAutoOn;
  document.getElementById("logAutoBtn").textContent=logAutoOn?"Auto ●":"Auto ○";
  if(logAutoOn){
    logAutoTimer=setInterval(reloadLogs,3000);
  } else {
    clearInterval(logAutoTimer);
  }
}

// ── inspect ────────────────────────────────────────────────────────────────
async function openInspect(cid,name){
  document.getElementById("tabInspect").textContent="Inspect: "+name;
  document.getElementById("tabInspect").style.display="";
  document.getElementById("inspectTitle").textContent="Inspect — "+name;
  switchTab("inspect");
  document.getElementById("inspectBody").textContent="Loading…";
  try{
    const r=await fetch("/api/inspect/"+cid);
    const j=await r.json();
    document.getElementById("inspectBody").textContent=JSON.stringify(j,null,2);
  } catch(e){
    document.getElementById("inspectBody").textContent="Error: "+e.message;
  }
}

// ── tabs ───────────────────────────────────────────────────────────────────
function switchTab(t){
  activeTab=t;
  document.querySelectorAll(".tab").forEach(el=>el.classList.toggle("on",el.dataset.t===t));
  document.querySelectorAll(".tpanel").forEach(el=>el.hidden=(el.id!=="panel-"+t));
  if(t==="events") renderEvents();
}
document.querySelectorAll(".tab").forEach(el=>
  el.addEventListener("click",()=>switchTab(el.dataset.t))
);

// ── sort / filter ──────────────────────────────────────────────────────────
document.querySelectorAll("thead th[data-k]").forEach(th=>
  th.addEventListener("click",()=>{
    const k=th.dataset.k;
    if(sortKey===k) sortDir*=-1;
    else{ sortKey=k; sortDir=(["name","image","state","id","ports"].includes(k)?1:-1); }
    render();
  })
);
document.getElementById("q").addEventListener("input",render);
document.getElementById("stateSeg").addEventListener("click",e=>{
  const b=e.target.closest("button"); if(!b) return;
  stateFilter=b.dataset.s;
  document.querySelectorAll("#stateSeg button").forEach(x=>x.classList.toggle("on",x===b));
  render();
});
document.getElementById("evq").addEventListener("input",renderEvents);

// ── timer ──────────────────────────────────────────────────────────────────
function setTimer(){
  if(timer) clearInterval(timer);
  const iv=+document.getElementById("iv").value;
  if(iv>0) timer=setInterval(()=>{poll();pollEvents();},iv);
}
document.getElementById("iv").addEventListener("change",setTimer);

poll(); pollEvents(); setTimer();
// poll events on a slower fixed cadence too
setInterval(pollEvents,8000);
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="dockmon — Docker monitoring dashboard")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--user", default=os.environ.get("DOCKMON_USER", ""),
                    help="Basic-auth username (env: DOCKMON_USER)")
    ap.add_argument("--password", default=os.environ.get("DOCKMON_PASSWORD", ""),
                    help="Basic-auth password (env: DOCKMON_PASSWORD)")
    args = ap.parse_args()

    if args.user and args.password:
        _set_auth(args.user, args.password)
        auth_status = f"auth enabled (user: {args.user})"
    elif args.user or args.password:
        ap.error("--user and --password must both be set to enable basic auth")
    else:
        auth_status = "auth disabled (set --user and --password to enable)"

    t = threading.Thread(target=_event_watcher, daemon=True)
    t.start()

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"dockmon listening on http://{args.bind}:{args.port}  (API: {API_VERSION}, {auth_status})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()