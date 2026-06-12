FROM python:3.12-alpine

COPY dockmon.py /app/dockmon.py

EXPOSE 8090

# No pip deps — stdlib only
ENTRYPOINT ["python3", "/app/dockmon.py", "--bind", "0.0.0.0", "--port", "8090"]