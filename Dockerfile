FROM python:3.13-alpine

RUN pip install --no-cache-dir esptool websocket-client cryptography paho-mqtt SQLAlchemy PyMySQL alembic

ENV PYTHONDONTWRITEBYTECODE=1
ENV OTA_RUNTIME_DIR=/addons/ota_server
ENV PYTHONPATH=/addons/ota_server

CMD ["/bin/sh", "/addons/ota_server/run.sh"]
