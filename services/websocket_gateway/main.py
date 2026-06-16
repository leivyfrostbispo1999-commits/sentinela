import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

try:
    import nats
    import websockets
except ImportError:
    nats = None
    websockets = None


NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
ALERTS_SUBJECT = os.getenv("ALERTS_SUBJECT", "sentinela.alerts.detections")
WEBSOCKET_HOST = os.getenv("WEBSOCKET_HOST", "0.0.0.0")
WEBSOCKET_PORT = int(os.getenv("WEBSOCKET_PORT", "8765"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "8013"))

CLIENTS = set()
MESSAGES_SENT = Counter("sentinela_ws_gateway_messages_sent_total", "Messages sent to websocket clients")
CLIENTS_GAUGE = Gauge("sentinela_ws_gateway_clients", "Connected websocket clients")
NATS_CONNECTED = Gauge("sentinela_ws_gateway_nats_connected", "NATS connection state")
MALFORMED_MESSAGES = Counter("sentinela_ws_gateway_malformed_messages_total", "Malformed bus messages")


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200 if NATS_CONNECTED._value.get() else 503)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/metrics":
            payload = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        return


def start_metrics():
    server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), MetricsHandler)
    Thread(target=server.serve_forever, daemon=True).start()


async def connect_nats():
    delay = 1
    while True:
        try:
            nc = await nats.connect(
                servers=[NATS_URL], reconnect_time_wait=2, max_reconnect_attempts=-1, name="sentinela-websocket-gateway"
            )
            NATS_CONNECTED.set(1)
            return nc
        except Exception as exc:
            NATS_CONNECTED.set(0)
            print(
                json.dumps(
                    {
                        "level": "WARN",
                        "component": "websocket_gateway",
                        "message": "Waiting for NATS",
                        "error": str(exc),
                        "retry_in_seconds": delay,
                    }
                ),
                flush=True,
            )
            await asyncio.sleep(delay)
            delay = min(15, delay * 2)


async def ws_handler(websocket):
    CLIENTS.add(websocket)
    CLIENTS_GAUGE.set(len(CLIENTS))
    try:
        await websocket.send(json.dumps({"type": "ready", "source": "sentinela-websocket-gateway"}))
        await websocket.wait_closed()
    finally:
        CLIENTS.discard(websocket)
        CLIENTS_GAUGE.set(len(CLIENTS))


def encode_alert(alert):
    return json.dumps({"type": "alert", "data": alert}, ensure_ascii=False)


async def broadcast(alert):
    if not CLIENTS:
        return
    payload = encode_alert(alert)
    dead = []
    for client in CLIENTS:
        try:
            await client.send(payload)
            MESSAGES_SENT.inc()
        except Exception:
            dead.append(client)
    for client in dead:
        CLIENTS.discard(client)
    CLIENTS_GAUGE.set(len(CLIENTS))


async def handle_bus_message(data):
    try:
        alert = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        MALFORMED_MESSAGES.inc()
        return False
    await broadcast(alert)
    return True


async def main():
    if not nats or not websockets:
        raise RuntimeError("nats-py and websockets are required")
    start_metrics()
    nc = await connect_nats()

    async def handler(msg):
        await handle_bus_message(msg.data)

    await nc.subscribe(ALERTS_SUBJECT, cb=handler)
    async with websockets.serve(ws_handler, WEBSOCKET_HOST, WEBSOCKET_PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
