#!/usr/bin/env python3
"""
dockmon — single-file Docker container monitoring dashboard.

Zero pip dependencies (stdlib only). Talks to the Docker Engine API
over /var/run/docker.sock and serves a live dashboard with sorting,
filtering, per-container CPU/memory gauges and sparkline history.

Run (your user is not in the docker group, so use sudo):

    sudo python3 dockmon.py            # http://0.0.0.0:8090
    sudo python3 dockmon.py --port 9000 --bind 127.0.0.1

Then open http://<host>:8090 in a browser.
"""

import argparse
import http.client
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DOCKER_SOCK = "/var/run/docker.sock"
API_VERSION = "v1.41"

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


def docker_get(path, timeout=10):
    conn = UnixHTTPConnection(DOCKER_SOCK, timeout=timeout)
    try:
        conn.request("GET", f"/{API_VERSION}{path}")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status >= 400:
            raise RuntimeError(f"Docker API {resp.status}: {body[:200]!r}")
        return json.loads(body)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Stats collection
# ---------------------------------------------------------------------------

_prev_io = {}          # container id -> {"t": ts, "rx": n, "tx": n, "br": n, "bw": n}
_prev_io_lock = threading.Lock()


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
        # subtract page cache like `docker stats` does
        s = m.get("stats", {}) or {}
        cache = s.get("inactive_file", s.get("total_inactive_file", s.get("cache", 0))) or 0
        usage = max(usage - cache, 0)
        limit = m.get("limit", 0)
        pct = (usage / limit * 100.0) if limit else 0.0
        return usage, limit, pct
    except (KeyError, TypeError):
        return 0, 0, 0.0


def _calc_io(stats):
    rx = tx = 0
    for iface in (stats.get("networks") or {}).values():
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    br = bw = 0
    for entry in (stats.get("blkio_stats", {}).get("io_service_bytes_recursive") or []):
        op = entry.get("op", "").lower()
        if op == "read":
            br += entry.get("value", 0)
        elif op == "write":
            bw += entry.get("value", 0)
    return rx, tx, br, bw


def _fetch_one(c):
    cid = c["Id"]
    name = (c.get("Names") or ["/?"])[0].lstrip("/")
    base = {
        "id": cid[:12],
        "name": name,
        "image": c.get("Image", ""),
        "state": c.get("State", ""),
        "status": c.get("Status", ""),
        "created": c.get("Created", 0),
        "cpu": 0.0, "mem_used": 0, "mem_limit": 0, "mem_pct": 0.0,
        "net_rx": 0, "net_tx": 0, "net_rx_rate": 0.0, "net_tx_rate": 0.0,
        "blk_r": 0, "blk_w": 0, "pids": 0,
    }
    if c.get("State") != "running":
        return base
    try:
        stats = docker_get(f"/containers/{cid}/stats?stream=false&one-shot=false", timeout=8)
    except Exception:
        return base

    base["cpu"] = round(_calc_cpu_percent(stats), 2)
    used, limit, pct = _calc_mem(stats)
    base["mem_used"], base["mem_limit"], base["mem_pct"] = used, limit, round(pct, 2)
    rx, tx, br, bw = _calc_io(stats)
    base["net_rx"], base["net_tx"], base["blk_r"], base["blk_w"] = rx, tx, br, bw
    base["pids"] = (stats.get("pids_stats") or {}).get("current", 0)

    now = time.time()
    with _prev_io_lock:
        prev = _prev_io.get(cid)
        _prev_io[cid] = {"t": now, "rx": rx, "tx": tx}
    if prev and now > prev["t"]:
        dt = now - prev["t"]
        base["net_rx_rate"] = round(max(rx - prev["rx"], 0) / dt, 1)
        base["net_tx_rate"] = round(max(tx - prev["tx"], 0) / dt, 1)
    return base


def collect_stats():
    containers = docker_get("/containers/json?all=1")
    results = []
    with ThreadPoolExecutor(max_workers=min(16, max(4, len(containers)))) as ex:
        futs = [ex.submit(_fetch_one, c) for c in containers]
        for f in as_completed(futs):
            results.append(f.result())
    # prune rate cache of dead containers
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
        }
    except Exception:
        pass
    return {"ts": time.time(), "host": info, "containers": results}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "dockmon/1.0"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/stats":
            try:
                payload = collect_stats()
                self._send(200, json.dumps(payload), "application/json")
            except FileNotFoundError:
                self._send(500, json.dumps({"error": f"Cannot reach {DOCKER_SOCK}. Is Docker running? Run dockmon with sudo."}), "application/json")
            except PermissionError:
                self._send(500, json.dumps({"error": f"Permission denied on {DOCKER_SOCK}. Run dockmon with sudo."}), "application/json")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}), "application/json")
        elif self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")


# ---------------------------------------------------------------------------
# Frontend (embedded, no CDN dependencies)
# ---------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockmon</title>
<style>
:root{
  --bg:#10151c; --panel:#161d27; --panel-2:#1c2533; --line:#27313f;
  --text:#d7dee8; --dim:#7d8a9b; --faint:#566374;
  --copper:#e8a25c; --copper-dim:#a06a35;
  --ok:#5fb88a; --warn:#e0b14e; --hot:#e06a5a; --blue:#6aa5d8;
  --mono:ui-monospace,'SF Mono','Cascadia Mono','JetBrains Mono',Menlo,Consolas,monospace;
  --sans:'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px}
a{color:var(--copper)}

header{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;
  padding:18px 22px 12px;border-bottom:1px solid var(--line)}
header h1{font-family:var(--mono);font-size:17px;font-weight:600;letter-spacing:.04em;color:var(--copper)}
header h1 .dot{color:var(--ok)}
#hostline{font-family:var(--mono);font-size:12px;color:var(--dim)}
#err{font-family:var(--mono);font-size:12px;color:var(--hot);width:100%}

.totals{display:flex;gap:26px;flex-wrap:wrap;padding:12px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
.tot{font-family:var(--mono)}
.tot .v{font-size:19px;color:var(--text)}
.tot .v b{color:var(--copper);font-weight:600}
.tot .k{display:block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-top:2px}

.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:12px 22px}
.controls input[type=text]{background:var(--panel);border:1px solid var(--line);color:var(--text);
  font-family:var(--mono);font-size:13px;padding:7px 10px;border-radius:4px;width:260px;outline:none}
.controls input[type=text]:focus{border-color:var(--copper-dim)}
.seg{display:flex;border:1px solid var(--line);border-radius:4px;overflow:hidden}
.seg button{background:var(--panel);border:0;color:var(--dim);font-family:var(--mono);font-size:12px;
  padding:7px 12px;cursor:pointer}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:var(--panel-2);color:var(--copper)}
.seg button:focus-visible{outline:2px solid var(--copper);outline-offset:-2px}
.controls label{font-family:var(--mono);font-size:11px;color:var(--faint);letter-spacing:.08em;text-transform:uppercase}
.controls select{background:var(--panel);border:1px solid var(--line);color:var(--text);
  font-family:var(--mono);font-size:12px;padding:6px 8px;border-radius:4px}
#count{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--faint)}

.wrap{padding:0 22px 40px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12.5px}
thead th{position:sticky;top:0;background:var(--bg);text-align:left;font-weight:500;
  font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);
  padding:9px 10px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:var(--dim)}
thead th.sorted{color:var(--copper)}
thead th .arr{font-size:9px;margin-left:3px}
tbody td{padding:8px 10px;border-bottom:1px solid #1b2330;vertical-align:middle;white-space:nowrap}
tbody tr:hover{background:var(--panel)}
td.name{color:var(--text);font-weight:600;max-width:240px;overflow:hidden;text-overflow:ellipsis}
td.img{color:var(--dim);max-width:220px;overflow:hidden;text-overflow:ellipsis}
td.id{color:var(--faint)}
.state{display:inline-block;font-size:10.5px;padding:2px 7px;border-radius:3px;letter-spacing:.05em}
.state.running{color:var(--ok);background:rgba(95,184,138,.1)}
.state.exited{color:var(--faint);background:rgba(125,138,155,.1)}
.state.paused{color:var(--warn);background:rgba(224,177,78,.1)}
.state.restarting{color:var(--hot);background:rgba(224,106,90,.12)}

.gauge{display:flex;align-items:center;gap:8px;min-width:150px}
.gauge .num{width:62px;text-align:right;color:var(--text)}
.bar{flex:1;height:5px;background:var(--panel-2);border-radius:3px;overflow:hidden;min-width:60px}
.bar i{display:block;height:100%;border-radius:3px;background:var(--ok);transition:width .4s ease}
.bar i.warn{background:var(--warn)} .bar i.hot{background:var(--hot)}
.sub{color:var(--faint);font-size:11px}
canvas.spark{display:block;width:88px;height:22px}
.rate{color:var(--blue)}
.empty{padding:50px;text-align:center;color:var(--faint);font-family:var(--mono)}
@media (prefers-reduced-motion: reduce){ .bar i{transition:none} }
@media (max-width:760px){ .controls input[type=text]{width:100%} }
</style>
</head>
<body>
<header>
  <h1><span class="dot">●</span> dockmon</h1>
  <span id="hostline">connecting…</span>
  <span id="err"></span>
</header>

<div class="totals">
  <div class="tot"><span class="v" id="t-run">–</span><span class="k">running / total</span></div>
  <div class="tot"><span class="v" id="t-cpu">–</span><span class="k">Σ cpu</span></div>
  <div class="tot"><span class="v" id="t-mem">–</span><span class="k">Σ memory</span></div>
  <div class="tot"><span class="v" id="t-net">–</span><span class="k">Σ net rx/tx rate</span></div>
</div>

<div class="controls">
  <input id="q" type="text" placeholder="filter by name / image / id…" autocomplete="off">
  <div class="seg" id="stateSeg" role="group" aria-label="State filter">
    <button data-s="all" class="on">all</button>
    <button data-s="running">running</button>
    <button data-s="exited">exited</button>
    <button data-s="paused">paused</button>
  </div>
  <label for="iv">refresh</label>
  <select id="iv">
    <option value="2000">2s</option>
    <option value="5000" selected>5s</option>
    <option value="10000">10s</option>
    <option value="30000">30s</option>
    <option value="0">paused</option>
  </select>
  <span id="count"></span>
</div>

<div class="wrap">
<table>
  <thead><tr>
    <th data-k="name">Name<span class="arr"></span></th>
    <th data-k="state">State<span class="arr"></span></th>
    <th data-k="cpu">CPU %<span class="arr"></span></th>
    <th>CPU trend</th>
    <th data-k="mem_used">Memory<span class="arr"></span></th>
    <th data-k="net_rx_rate">Net RX/s<span class="arr"></span></th>
    <th data-k="net_tx_rate">Net TX/s<span class="arr"></span></th>
    <th data-k="blk_r">Disk R<span class="arr"></span></th>
    <th data-k="blk_w">Disk W<span class="arr"></span></th>
    <th data-k="pids">PIDs<span class="arr"></span></th>
    <th data-k="image">Image<span class="arr"></span></th>
    <th data-k="id">ID<span class="arr"></span></th>
  </tr></thead>
  <tbody id="rows"></tbody>
</table>
<div class="empty" id="empty" hidden>No containers match.</div>
</div>

<script>
"use strict";
let DATA = [], HIST = {}, sortKey = "cpu", sortDir = -1, stateFilter = "all", timer = null;
const HIST_LEN = 40;

const fmtB = n => {
  if (!n) return "0 B";
  const u = ["B","KB","MB","GB","TB"]; let i = 0;
  while (n >= 1024 && i < u.length-1) { n /= 1024; i++; }
  return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
};
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

async function poll() {
  try {
    const r = await fetch("/api/stats");
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    document.getElementById("err").textContent = "";
    DATA = j.containers;
    const h = j.host || {};
    document.getElementById("hostline").textContent =
      (h.host ? h.host + " · " : "") + (h.docker_version ? "docker " + h.docker_version + " · " : "")
      + (h.ncpu ? h.ncpu + " cpu · " : "") + (h.mem_total ? fmtB(h.mem_total) + " ram" : "");
    for (const c of DATA) {
      if (c.state !== "running") continue;
      (HIST[c.id] = HIST[c.id] || []).push(c.cpu);
      if (HIST[c.id].length > HIST_LEN) HIST[c.id].shift();
    }
    render();
  } catch (e) {
    document.getElementById("err").textContent = "⚠ " + e.message;
  }
}

function render() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  let rows = DATA.filter(c =>
    (stateFilter === "all" || c.state === stateFilter) &&
    (!q || c.name.toLowerCase().includes(q) || c.image.toLowerCase().includes(q) || c.id.includes(q))
  );
  rows.sort((a,b) => {
    const x = a[sortKey], y = b[sortKey];
    const r = (typeof x === "string") ? x.localeCompare(y) : (x - y);
    return r * sortDir;
  });

  const running = DATA.filter(c => c.state === "running");
  document.getElementById("t-run").innerHTML = "<b>" + running.length + "</b> / " + DATA.length;
  document.getElementById("t-cpu").textContent = running.reduce((s,c)=>s+c.cpu,0).toFixed(1) + " %";
  document.getElementById("t-mem").textContent = fmtB(running.reduce((s,c)=>s+c.mem_used,0));
  document.getElementById("t-net").textContent =
    fmtB(running.reduce((s,c)=>s+c.net_rx_rate,0)) + " / " + fmtB(running.reduce((s,c)=>s+c.net_tx_rate,0));
  document.getElementById("count").textContent = rows.length + " shown";
  document.getElementById("empty").hidden = rows.length > 0;

  const tb = document.getElementById("rows");
  tb.innerHTML = rows.map(c => {
    const cpuCls = c.cpu > 85 ? "hot" : c.cpu > 50 ? "warn" : "";
    const memCls = c.mem_pct > 85 ? "hot" : c.mem_pct > 60 ? "warn" : "";
    const run = c.state === "running";
    return `<tr>
      <td class="name" title="${esc(c.name)}">${esc(c.name)}</td>
      <td><span class="state ${esc(c.state)}">${esc(c.state)}</span></td>
      <td>${run ? `<div class="gauge"><span class="num">${c.cpu.toFixed(1)}%</span>
        <span class="bar"><i class="${cpuCls}" style="width:${Math.min(c.cpu,100)}%"></i></span></div>` : '<span class="sub">—</span>'}</td>
      <td>${run ? `<canvas class="spark" data-id="${esc(c.id)}" width="176" height="44"></canvas>` : ''}</td>
      <td>${run ? `<div class="gauge"><span class="num">${fmtB(c.mem_used)}</span>
        <span class="bar"><i class="${memCls}" style="width:${Math.min(c.mem_pct,100)}%"></i></span>
        <span class="sub">/ ${fmtB(c.mem_limit)}</span></div>` : '<span class="sub">—</span>'}</td>
      <td class="rate">${run ? fmtB(c.net_rx_rate)+"/s" : ""}</td>
      <td class="rate">${run ? fmtB(c.net_tx_rate)+"/s" : ""}</td>
      <td class="sub">${run ? fmtB(c.blk_r) : ""}</td>
      <td class="sub">${run ? fmtB(c.blk_w) : ""}</td>
      <td class="sub">${run ? c.pids : ""}</td>
      <td class="img" title="${esc(c.image)}">${esc(c.image)}</td>
      <td class="id">${esc(c.id)}</td>
    </tr>`;
  }).join("");

  document.querySelectorAll("canvas.spark").forEach(cv => {
    const h = HIST[cv.dataset.id] || [];
    const ctx = cv.getContext("2d");
    ctx.clearRect(0,0,cv.width,cv.height);
    if (h.length < 2) return;
    const max = Math.max(10, ...h), W = cv.width, H = cv.height, step = W/(HIST_LEN-1);
    ctx.beginPath();
    h.forEach((v,i) => {
      const x = W - (h.length-1-i)*step, y = H - 3 - (v/max)*(H-6);
      i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.strokeStyle = "#e8a25c"; ctx.lineWidth = 2; ctx.stroke();
  });

  document.querySelectorAll("thead th[data-k]").forEach(th => {
    const on = th.dataset.k === sortKey;
    th.classList.toggle("sorted", on);
    th.querySelector(".arr").textContent = on ? (sortDir === -1 ? "▼" : "▲") : "";
  });
}

document.querySelectorAll("thead th[data-k]").forEach(th =>
  th.addEventListener("click", () => {
    const k = th.dataset.k;
    if (sortKey === k) sortDir *= -1;
    else { sortKey = k; sortDir = (k === "name" || k === "image" || k === "state" || k === "id") ? 1 : -1; }
    render();
  })
);
document.getElementById("q").addEventListener("input", render);
document.getElementById("stateSeg").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  stateFilter = b.dataset.s;
  document.querySelectorAll("#stateSeg button").forEach(x => x.classList.toggle("on", x === b));
  render();
});
function setTimer() {
  if (timer) clearInterval(timer);
  const iv = +document.getElementById("iv").value;
  if (iv > 0) timer = setInterval(poll, iv);
}
document.getElementById("iv").addEventListener("change", setTimer);

poll(); setTimer();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="dockmon — Docker monitoring dashboard")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"dockmon listening on http://{args.bind}:{args.port}  (docker socket: {DOCKER_SOCK})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
