FROM python:3.11-slim

# 唯一进程：纯标准库实现的 WebSocket 回显服务
WORKDIR /srv
COPY app/ ./app/

ENV WS_HOST=0.0.0.0 \
    WS_PORT=8080 \
    WS_CLOSE_TIMEOUT=5 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=4s --start-period=3s --retries=3 \
    CMD ["python", "-m", "app.healthcheck"]

# 直接前台运行，不经过 shell/ supervisor，容器内只有这一个监听进程
CMD ["python", "-m", "app.server"]
