from __future__ import annotations

import json
import time

import activity
import server_mysql


server = server_mysql.server
BaseUIHandler = server.UIHandler


class LiveUIHandler(BaseUIHandler):
    protocol_version = 'HTTP/1.1'

    def _send_sse_activity(self, row) -> None:
        payload = {
            'id': int(row['id']),
            'time': activity._compact_time(row['created_at']),
            'category': str(row['category'] or 'OTHER').upper(),
            'severity': str(row['severity'] or 'INFO').upper(),
            'device_id': str(row['device_id'] or ''),
            'action': str(row['action'] or ''),
            'detail': str(row['detail'] or ''),
        }
        data = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
        self.wfile.write(f'id: {payload["id"]}\nevent: activity\ndata: {data}\n\n'.encode('utf-8'))
        self.wfile.flush()

    def _activity_events(self, parsed) -> None:
        query = server.urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        try:
            after = max(0, int((query.get('after') or ['0'])[0]))
        except (TypeError, ValueError):
            after = 0

        last_event_id = self.headers.get('Last-Event-ID')
        if last_event_id:
            try:
                after = max(after, int(last_event_id))
            except ValueError:
                pass

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-transform')
        self.send_header('Connection', 'keep-alive')
        self.send_header('X-Accel-Buffering', 'no')
        self.end_headers()
        self.wfile.write(b'retry: 1500\n\n')
        self.wfile.flush()

        last_id = after
        keepalive_at = time.monotonic()
        try:
            while True:
                with server_mysql.db_connect() as conn:
                    rows = conn.execute(
                        'SELECT id, created_at, category, severity, device_id, action, detail '
                        'FROM activity_log WHERE id > ? ORDER BY id ASC LIMIT 100',
                        (last_id,),
                    ).fetchall()

                for row in rows:
                    self._send_sse_activity(row)
                    last_id = int(row['id'])

                now = time.monotonic()
                if now - keepalive_at >= 15.0:
                    self.wfile.write(b': keepalive\n\n')
                    self.wfile.flush()
                    keepalive_at = now

                time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return

    def do_GET(self):
        parsed = server.urllib.parse.urlparse(self.path)
        if parsed.path.rstrip('/') == '/events':
            return self._activity_events(parsed)
        return super().do_GET()


server.UIHandler = LiveUIHandler


if __name__ == '__main__':
    print('Firmware publish HTTPS endpoint active: POST /api/firmware/publish handler=SecureOTAHandler', flush=True)
    print('Zigbee2MQTT publish HTTPS endpoint active: POST /api/zigbee2mqtt/publish', flush=True)
    print('Ingress lifecycle tables active: SSE activity stream + artifacts, provisioning attempts, ESP x firmware state', flush=True)
    print('Ingress live activity endpoint active: GET /events (SSE)', flush=True)
    server.start_servers()
