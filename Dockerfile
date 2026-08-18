FROM python:3.13-alpine

RUN pip install --no-cache-dir esptool websocket-client cryptography paho-mqtt

COPY run.sh /
COPY ota_helper.py /
COPY device_enrollment.py /
COPY server.py /
COPY mqtt_listener.py /
COPY device_enrollment.py /
COPY ota_tool.py /usr/local/bin/ota-tool

RUN chmod a+x /run.sh /usr/local/bin/ota-tool

CMD ["/run.sh"]
