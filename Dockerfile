FROM python:3.13-alpine

RUN pip install --no-cache-dir esptool websocket-client cryptography paho-mqtt SQLAlchemy PyMySQL alembic

COPY run.sh /
COPY ota_helper.py /
COPY device_enrollment.py /
COPY database.py /
COPY device_registry.py /
COPY manufacturing_api.py /
COPY migrate_legacy_sqlite.py /
COPY server.py /
COPY server_mysql.py /
COPY mqtt_listener.py /
COPY secure_transport.py /
COPY ota_tool.py /usr/local/bin/ota-tool
COPY alembic.ini /
COPY migrations /migrations

RUN chmod a+x /run.sh /usr/local/bin/ota-tool

CMD ["/run.sh"]
