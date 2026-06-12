FROM python:3.14-alpine

COPY dockmon.py /app/dockmon.py

EXPOSE 8090

ENTRYPOINT ["python3", "/app/dockmon.py", "--bind", "0.0.0.0", "--port", "8090"]
