FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY ws_echo_server.py .

EXPOSE 8080
# Single listening process; frames/message state handled in-process.
CMD ["python", "ws_echo_server.py"]
