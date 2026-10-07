"""Modbus TCP Protocol Server for GhostGrid.

Implements an asynchronous Modbus TCP server answering requests from live physical state.
Enforces protocol compliance:
- Sub-millisecond latency (database writes queued in background thread).
- Modbus exception 0x02 (ILLEGAL_DATA_ADDRESS) for unmapped registers.
- Modbus exception 0x03 (ILLEGAL_DATA_VALUE) for invalid coil values or oversized requests.
- All probe attempts and exception responses logged to SOC database.
- Fixed Unit 0 broadcast handling (always consumes full PDU so stream is never desynchronized).
- Clean shutdown on Python 3.12+/3.14 without hanging.
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import struct
import sys
import time
from typing import Dict, Optional, Set
from ghostgrid.core.identity import SiteIdentity, TagDefinition
from ghostgrid.core.state import StateEngine
from ghostgrid.core.logger import EventLogger
from ghostgrid.core.protocol.frames import (
    ModbusFunction,
    ModbusException,
    parse_mbap_header,
    build_exception_response,
    build_read_bits_response,
    build_read_words_response,
    build_write_single_response,
    build_write_multiple_response,
    build_device_id_response,
)

logger = logging.getLogger("ghostgrid.protocol")

# Enable 1ms timer resolution on Windows so response_delay_ms sleeps precisely
if sys.platform == "win32":
    try:
        ctypes.windll.winmm.timeBeginPeriod(1)
    except Exception:
        pass


class ModbusServer:
    """Asynchronous Modbus TCP server backed by live physical state engine."""

    def __init__(
        self,
        host: str,
        port: int,
        unit_id: int,
        state_engine: StateEngine,
        identity: SiteIdentity,
        event_logger: EventLogger,
        response_delay_ms: int = 2,
        allow_broadcast: bool = False,
        max_clients: int = 64,
        max_clients_per_ip: int = 16,
        idle_timeout_s: float = 1800.0,
    ):
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.state = state_engine
        self.identity = identity
        self.logger = event_logger
        self.response_delay_ms = response_delay_ms
        self.allow_broadcast = allow_broadcast
        # Resource ceilings: one visitor opening thousands of sockets must not exhaust the decoy.
        # Real PLCs also have a small, fixed connection table and drop connections beyond it.
        self.max_clients = max_clients
        self.max_clients_per_ip = max_clients_per_ip
        # Long on purpose: keeping a visitor connected is the point, but abandoned sockets must not pile up.
        self.idle_timeout_s = idle_timeout_s

        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._client_tasks: Set[asyncio.Task] = set()
        self._active_writers: Set[asyncio.StreamWriter] = set()
        self._clients_per_ip: Dict[str, int] = {}

    async def start(self):
        """Start listening on the configured Modbus TCP socket."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        self._running = True
        addrs = ", ".join(str(sock.getsockname()) for sock in self._server.sockets)
        logger.info("GhostGrid Modbus TCP server listening on %s (Unit ID: %d)", addrs, self.unit_id)

    async def stop(self):
        """Stop the Modbus TCP server and cleanly terminate connected clients."""
        self._running = False

        # First close active client writers and cancel client tasks
        for writer in list(self._active_writers):
            try:
                writer.close()
            except Exception:
                pass

        for task in list(self._client_tasks):
            task.cancel()

        if self._client_tasks:
            await asyncio.gather(*self._client_tasks, return_exceptions=True)
        self._client_tasks.clear()
        self._active_writers.clear()

        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                pass
        logger.info("GhostGrid Modbus TCP server stopped cleanly")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an individual incoming attacker or scanner connection."""
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        client_port = peer[1] if peer else 0

        if (len(self._active_writers) >= self.max_clients
                or self._clients_per_ip.get(client_ip, 0) >= self.max_clients_per_ip):
            logger.warning("[!] Connection limit reached, refusing %s:%d (%d open, %d from this address)",
                           client_ip, client_port, len(self._active_writers),
                           self._clients_per_ip.get(client_ip, 0))
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        current_task = asyncio.current_task()
        if current_task:
            self._client_tasks.add(current_task)
        self._active_writers.add(writer)
        self._clients_per_ip[client_ip] = self._clients_per_ip.get(client_ip, 0) + 1

        session_id = self.logger.start_session(client_ip, client_port, self.unit_id)
        logger.info("[+] New Modbus connection: %s:%d (Session %s)", client_ip, client_port, session_id[:8])

        try:
            while self._running:
                try:
                    header_bytes = await asyncio.wait_for(reader.readexactly(7), self.idle_timeout_s)
                except asyncio.TimeoutError:
                    logger.info("[-] Idle timeout: %s:%d sent nothing for %.0f s", client_ip, client_port,
                                self.idle_timeout_s)
                    break
                except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.CancelledError):
                    break

                mbap = parse_mbap_header(header_bytes)
                if not mbap:
                    break
                trans_id, proto_id, length, req_unit_id = mbap

                if proto_id != 0:
                    break

                pdu_len = length - 1
                if pdu_len <= 0 or pdu_len > 260:
                    break

                # CRITICAL: Always read PDU bytes completely BEFORE evaluating unit ID
                # so the TCP stream is never desynchronized on broadcast or filtered packets
                try:
                    pdu_bytes = await asyncio.wait_for(reader.readexactly(pdu_len), self.idle_timeout_s)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError,
                        asyncio.CancelledError):
                    break

                # Broadcast handling: Unit 0 is Modbus broadcast (standard Modbus never returns response)
                if req_unit_id == 0:
                    if self.allow_broadcast:
                        self._process_pdu(trans_id, req_unit_id, pdu_bytes, session_id, client_ip)
                    continue

                # _process_pdu logs each request with its own processing time.
                resp_bytes = self._process_pdu(trans_id, req_unit_id, pdu_bytes, session_id, client_ip)

                if self.response_delay_ms > 0:
                    await asyncio.sleep(self.response_delay_ms / 1000.0)

                try:
                    writer.write(resp_bytes)
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Exception in client handler %s:%d: %s", client_ip, client_port, e, exc_info=True)
        finally:
            self.logger.end_session(session_id)
            self._active_writers.discard(writer)
            remaining = self._clients_per_ip.get(client_ip, 1) - 1
            if remaining > 0:
                self._clients_per_ip[client_ip] = remaining
            else:
                self._clients_per_ip.pop(client_ip, None)
            if current_task:
                self._client_tasks.discard(current_task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("[-] Modbus connection closed: %s:%d (Session %s)", client_ip, client_port, session_id[:8])

    def _is_ht_address(self, addr: int, tag: Optional[TagDefinition]) -> bool:
        """Check if an address is flagged as a honeytoken trap."""
        if tag and tag.is_honeytoken:
            return True
        if addr in self.logger.honeytoken_registers or (addr + 40001) in self.logger.honeytoken_registers:
            return True
        return False

    def _process_pdu(self, trans_id: int, unit_id: int, pdu: bytes, session_id: str, client_ip: str) -> bytes:
        """Decode and execute Modbus PDU against live state engine and log all events."""
        fc = pdu[0]
        data = pdu[1:]
        t_start = time.perf_counter()

        try:
            # 0x01: Read Coils
            if fc == ModbusFunction.READ_COILS:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Read Coils", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count = struct.unpack(">HH", data[:4])
                if count < 1 or count > 2000:
                    self.logger.log_request(session_id, fc, "Read Coils", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                bits, tags = self.state.read_coils(start_addr, count)
                if bits is None or tags is None:
                    self.logger.log_request(session_id, fc, "Read Coils", start_addr, count, None, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                primary_tag = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"Coil_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Read Coils", start_addr, count, bits, latency, "SUCCESS", primary_tag, is_ht, client_ip)
                return build_read_bits_response(trans_id, unit_id, fc, bits)

            # 0x02: Read Discrete Inputs
            elif fc == ModbusFunction.READ_DISCRETE_INPUTS:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Read Discrete Inputs", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count = struct.unpack(">HH", data[:4])
                if count < 1 or count > 2000:
                    self.logger.log_request(session_id, fc, "Read Discrete Inputs", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                bits, tags = self.state.read_discrete_inputs(start_addr, count)
                if bits is None or tags is None:
                    self.logger.log_request(session_id, fc, "Read Discrete Inputs", start_addr, count, None, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                primary_tag = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"Discrete_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Read Discrete Inputs", start_addr, count, bits, latency, "SUCCESS", primary_tag, is_ht, client_ip)
                return build_read_bits_response(trans_id, unit_id, fc, bits)

            # 0x03: Read Holding Registers
            elif fc == ModbusFunction.READ_HOLDING_REGISTERS:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Read Holding Registers", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count = struct.unpack(">HH", data[:4])
                if count < 1 or count > 125:
                    self.logger.log_request(session_id, fc, "Read Holding Registers", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                words, tags = self.state.read_holding_registers(start_addr, count)
                if words is None or tags is None:
                    self.logger.log_request(session_id, fc, "Read Holding Registers", start_addr, count, None, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                primary_tag = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"HR_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Read Holding Registers", start_addr, count, words, latency, "SUCCESS", primary_tag, is_ht, client_ip)
                return build_read_words_response(trans_id, unit_id, fc, words)

            # 0x04: Read Input Registers
            elif fc == ModbusFunction.READ_INPUT_REGISTERS:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Read Input Registers", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count = struct.unpack(">HH", data[:4])
                if count < 1 or count > 125:
                    self.logger.log_request(session_id, fc, "Read Input Registers", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                words, tags = self.state.read_input_registers(start_addr, count)
                if words is None or tags is None:
                    self.logger.log_request(session_id, fc, "Read Input Registers", start_addr, count, None, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                primary_tag = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"IR_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Read Input Registers", start_addr, count, words, latency, "SUCCESS", primary_tag, is_ht, client_ip)
                return build_read_words_response(trans_id, unit_id, fc, words)

            # 0x05: Write Single Coil
            elif fc == ModbusFunction.WRITE_SINGLE_COIL:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Write Single Coil", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                addr, raw_val = struct.unpack(">HH", data[:4])

                # Modbus standard: 0xFF00 = ON, 0x0000 = OFF. Any other value is ILLEGAL_DATA_VALUE
                if raw_val not in (0x0000, 0xFF00):
                    self.logger.log_request(session_id, fc, "Write Single Coil", addr, 1, raw_val, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_VALUE", f"Coil_{addr}", False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                val = 1 if raw_val == 0xFF00 else 0
                tag = self.state.write_coil(addr, val)
                if not tag:
                    self.logger.log_request(session_id, fc, "Write Single Coil", addr, 1, val, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", f"Coil_{addr}", False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                is_ht = self._is_ht_address(addr, tag)
                tag_name = tag.name
                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Write Single Coil", addr, 1, val, latency, "SUCCESS", tag_name, is_ht, client_ip)
                return build_write_single_response(trans_id, unit_id, fc, addr, raw_val)

            # 0x06: Write Single Register
            elif fc == ModbusFunction.WRITE_SINGLE_REGISTER:
                if len(data) < 4:
                    self.logger.log_request(session_id, fc, "Write Single Register", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                addr, val = struct.unpack(">HH", data[:4])

                tag = self.state.write_holding_register(addr, val)
                if not tag:
                    self.logger.log_request(session_id, fc, "Write Single Register", addr, 1, val, (time.perf_counter() - t_start)*1000.0, "ILLEGAL_DATA_ADDRESS", f"HR_{addr}", False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                is_ht = self._is_ht_address(addr, tag)
                tag_name = tag.name
                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Write Single Register", addr, 1, val, latency, "SUCCESS", tag_name, is_ht, client_ip)
                return build_write_single_response(trans_id, unit_id, fc, addr, val)

            # 0x0F: Write Multiple Coils
            elif fc == ModbusFunction.WRITE_MULTIPLE_COILS:
                if len(data) < 5:
                    self.logger.log_request(session_id, fc, "Write Multiple Coils", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count, byte_count = struct.unpack(">HHB", data[:5])

                expected_bytes = (count + 7) // 8
                if count < 1 or count > 1968 or byte_count != expected_bytes or len(data) < 5 + byte_count:
                    self.logger.log_request(session_id, fc, "Write Multiple Coils", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                coil_data = data[5:5 + byte_count]
                vals = []
                for i in range(count):
                    byte_idx = i // 8
                    bit_idx = i % 8
                    b = coil_data[byte_idx] if byte_idx < len(coil_data) else 0
                    vals.append((b >> bit_idx) & 1)

                tags = self.state.write_multiple_coils(start_addr, vals)
                if tags is None:
                    self.logger.log_request(session_id, fc, "Write Multiple Coils", start_addr, count, vals, 0.1, "ILLEGAL_DATA_ADDRESS", f"Coil_{start_addr}", False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                tag_name = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"Coil_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Write Multiple Coils", start_addr, count, vals, latency, "SUCCESS", tag_name, is_ht, client_ip)
                return build_write_multiple_response(trans_id, unit_id, fc, start_addr, count)

            # 0x10: Write Multiple Registers
            elif fc == ModbusFunction.WRITE_MULTIPLE_REGISTERS:
                if len(data) < 5:
                    self.logger.log_request(session_id, fc, "Write Multiple Registers", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                start_addr, count, byte_count = struct.unpack(">HHB", data[:5])

                if count < 1 or count > 123 or byte_count != (count * 2) or len(data) < 5 + byte_count:
                    self.logger.log_request(session_id, fc, "Write Multiple Registers", start_addr, count, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                words = []
                for i in range(count):
                    w_val = struct.unpack(">H", data[5 + (i * 2): 7 + (i * 2)])[0]
                    words.append(w_val)

                tags = self.state.write_multiple_holding_registers(start_addr, words)
                if tags is None:
                    self.logger.log_request(session_id, fc, "Write Multiple Registers", start_addr, count, words, 0.1, "ILLEGAL_DATA_ADDRESS", f"HR_{start_addr}", False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)

                ht_tags = [t for t in tags if t and self._is_ht_address(t.address, t)]
                is_ht = bool(ht_tags)
                tag_name = ht_tags[0].name if is_ht else (tags[0].name if tags and tags[0] else f"HR_{start_addr}")

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Write Multiple Registers", start_addr, count, words, latency, "SUCCESS", tag_name, is_ht, client_ip)
                return build_write_multiple_response(trans_id, unit_id, fc, start_addr, count)

            # 0x2B: Encapsulated Interface Transport (Read Device Identification)
            elif fc == ModbusFunction.READ_DEVICE_IDENTIFICATION:
                if len(data) < 3:
                    self.logger.log_request(session_id, fc, "Read Device ID", 0, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)
                mei_type, read_device_id_code, object_id = struct.unpack(">BBB", data[:3])
                if mei_type != 0x0E:
                    self.logger.log_request(session_id, fc, "Read Device ID", 0, 0, None, 0.1, "ILLEGAL_FUNCTION", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_FUNCTION)

                all_objects = self.identity.get_device_info_objects()

                if read_device_id_code == 0x01:
                    filtered = {k: v for k, v in all_objects.items() if k in (0x00, 0x01, 0x02)}
                elif read_device_id_code == 0x02:
                    filtered = {k: v for k, v in all_objects.items() if k <= 0x06}
                elif read_device_id_code == 0x03:
                    filtered = all_objects
                elif read_device_id_code == 0x04:
                    if object_id not in all_objects:
                        self.logger.log_request(session_id, fc, "Read Device ID", object_id, 0, None, 0.1, "ILLEGAL_DATA_ADDRESS", None, False, client_ip)
                        return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_ADDRESS)
                    filtered = {object_id: all_objects[object_id]}
                else:
                    self.logger.log_request(session_id, fc, "Read Device ID", object_id, 0, None, 0.1, "ILLEGAL_DATA_VALUE", None, False, client_ip)
                    return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_DATA_VALUE)

                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, "Read Device Identification", object_id, len(filtered), filtered, latency, "SUCCESS", "MEI_DEVICE_INFO", False, client_ip)
                return build_device_id_response(trans_id, unit_id, mei_type, read_device_id_code, filtered)

            else:
                latency = (time.perf_counter() - t_start) * 1000.0
                self.logger.log_request(session_id, fc, f"Unsupported_0x{fc:02X}", 0, 0, None, latency, "ILLEGAL_FUNCTION", None, False, client_ip)
                return build_exception_response(trans_id, unit_id, fc, ModbusException.ILLEGAL_FUNCTION)

        except Exception as e:
            logger.error("Error executing Modbus FC 0x%02X: %s", fc, e, exc_info=True)
            return build_exception_response(trans_id, unit_id, fc, ModbusException.SLAVE_DEVICE_FAILURE)
