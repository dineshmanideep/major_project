"""Lightweight standalone MQTT TCP broker service for Classical Network Testbed.

Runs an untrusted MQTT relay server over standard TCP sockets. Supports MQTT 3.1.1
packet formats: CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE, SUBACK, PINGREQ,
PINGRESP, and DISCONNECT. Compatible with standard MQTT clients (paho-mqtt, mosquitto).

Can be executed directly:
    python3 -m classical_network.broker_service --port 18885
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import sys

from classical_network.config import DEFAULT_BROKER_HOST, DEFAULT_BROKER_PORT


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (ClassicalBroker) %(message)s")
logger = logging.getLogger("ClassicalBroker")


class ClassicalMqttBroker:
    """Asyncio-based pure-Python MQTT 3.1.1 relay server for the classical testbed."""

    def __init__(self, host: str = DEFAULT_BROKER_HOST, port: int = DEFAULT_BROKER_PORT) -> None:
        self.host = host
        self.port = port
        self.subscriptions: dict[str, set[asyncio.StreamWriter]] = {}
        self.server: asyncio.AbstractServer | None = None
        self._running = False

    def _matches(self, topic_filter: str, topic: str) -> bool:
        """Evaluate topic filter matching against a published topic path."""
        if topic_filter == "#":
            return True
        f_parts = topic_filter.split("/")
        t_parts = topic.split("/")
        if f_parts[-1] == "#":
            return t_parts[: len(f_parts) - 1] == f_parts[:-1]
        if len(f_parts) != len(t_parts):
            return False
        for fp, tp in zip(f_parts, t_parts):
            if fp != "+" and fp != tp:
                return False
        return True

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_address = writer.get_extra_info("peername")
        logger.debug("Client connected: %s", client_address)
        try:
            while self._running:
                b1 = await reader.read(1)
                if not b1:
                    break
                packet_type = b1[0] >> 4
                flags = b1[0] & 0x0F

                # Variable length integer decoder
                multiplier = 1
                length = 0
                while True:
                    lb = await reader.read(1)
                    if not lb:
                        break
                    digit = lb[0]
                    length += (digit & 127) * multiplier
                    if (digit & 128) == 0:
                        break
                    multiplier *= 128

                payload = await reader.readexactly(length) if length > 0 else b""

                # 1: CONNECT
                if packet_type == 1:
                    # Reply CONNACK: 0x20, length 2, flags 0, return code 0 (Accepted)
                    writer.write(bytes([0x20, 0x02, 0x00, 0x00]))
                    await writer.drain()

                # 8: SUBSCRIBE
                elif packet_type == 8:
                    packet_id = struct.unpack("!H", payload[:2])[0]
                    idx = 2
                    sub_ack_codes = []
                    while idx < len(payload):
                        topic_len = struct.unpack("!H", payload[idx : idx + 2])[0]
                        idx += 2
                        topic_filter = payload[idx : idx + topic_len].decode("utf-8")
                        idx += topic_len
                        qos = payload[idx]
                        idx += 1
                        if topic_filter not in self.subscriptions:
                            self.subscriptions[topic_filter] = set()
                        self.subscriptions[topic_filter].add(writer)
                        sub_ack_codes.append(qos)

                    # Reply SUBACK
                    suback_body = struct.pack("!H", packet_id) + bytes(sub_ack_codes)
                    writer.write(bytes([0x90, len(suback_body)]) + suback_body)
                    await writer.drain()

                # 3: PUBLISH
                elif packet_type == 3:
                    topic_len = struct.unpack("!H", payload[:2])[0]
                    topic = payload[2 : 2 + topic_len].decode("utf-8")
                    idx = 2 + topic_len
                    qos = (flags >> 1) & 0x03
                    packet_id = None
                    if qos > 0:
                        packet_id = struct.unpack("!H", payload[idx : idx + 2])[0]
                        idx += 2
                    msg_body = payload[idx:]

                    if qos == 1 and packet_id is not None:
                        # Reply PUBACK
                        writer.write(struct.pack("!BBH", 0x40, 0x02, packet_id))
                        await writer.drain()

                    # Relay opaque bytes to matching subscribers
                    for t_filter, writers in list(self.subscriptions.items()):
                        if self._matches(t_filter, topic):
                            f_body = struct.pack("!H", len(topic)) + topic.encode("utf-8") + msg_body
                            rl = len(f_body)
                            rl_bytes = []
                            val = rl
                            while True:
                                d = val % 128
                                val = val // 128
                                if val > 0:
                                    d |= 128
                                rl_bytes.append(d)
                                if val == 0:
                                    break
                            hdr = bytes([0x30]) + bytes(rl_bytes)
                            for w in list(writers):
                                try:
                                    w.write(hdr + f_body)
                                    await w.drain()
                                except Exception:
                                    writers.discard(w)

                # 12: PINGREQ
                elif packet_type == 12:
                    writer.write(bytes([0xD0, 0x00]))
                    await writer.drain()

                # 14: DISCONNECT
                elif packet_type == 14:
                    break

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            for writers in self.subscriptions.values():
                writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._running = True
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info("Classical MQTT Broker running on tcp://%s:%d (Untrusted Relay)", self.host, self.port)

    async def stop(self) -> None:
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Classical MQTT Broker stopped.")

    async def serve_forever(self) -> None:
        await self.start()
        try:
            if self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="MP-1 Classical Pure-Python MQTT Relay Broker")
    parser.add_argument("--host", default=DEFAULT_BROKER_HOST, help="TCP listen host")
    parser.add_argument("--port", type=int, default=DEFAULT_BROKER_PORT, help="TCP listen port")
    args = parser.parse_args()

    broker = ClassicalMqttBroker(args.host, args.port)
    try:
        asyncio.run(broker.serve_forever())
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting.")


if __name__ == "__main__":
    main()
