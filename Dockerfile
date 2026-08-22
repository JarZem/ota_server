FROM python:3.13-alpine

RUN pip install --no-cache-dir esptool websocket-client cryptography paho-mqtt SQLAlchemy PyMySQL alembic

# The image contains only a seed copy. At runtime bootstrap.sh mirrors the
# managed scripts to /share/ota_server/runtime and OTA executes them there.
# /share is persistent and visible outside the add-on container.
RUN mkdir -p /opt/ota_server_seed
COPY *.py /opt/ota_server_seed/
COPY alembic.ini /opt/ota_server_seed/alembic.ini
COPY migrations /opt/ota_server_seed/migrations
COPY tests /opt/ota_server_seed/tests
COPY run.sh /opt/ota_server_seed/run.sh
COPY restart.sh /opt/ota_server_seed/restart.sh
COPY bootstrap.sh /bootstrap.sh

RUN chmod a+x /bootstrap.sh \
    /opt/ota_server_seed/run.sh \
    /opt/ota_server_seed/restart.sh \
    /opt/ota_server_seed/ota_tool.py \
    /opt/ota_server_seed/tests/run_ota_e2e_live.py \
    /opt/ota_server_seed/tests/test_ota_e2e_live.py

CMD ["/bootstrap.sh"]
