"""Integration tests for Modbus TCP protocol server and exception handling."""
import asyncio
import os
import struct
import tempfile
import unittest

from ghostgrid.core.identity import generate_site_identity
from ghostgrid.profiles.water.simulation import WaterProfile
from ghostgrid.core.state.engine import StateEngine
from ghostgrid.core.logger.db import EventLogger
from ghostgrid.core.protocol.modbus_server import ModbusServer
from ghostgrid.core.protocol.frames import ModbusFunction, ModbusException


class TestProtocolAndServer(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_soc.db")
        self.logger = EventLogger(self.db_path)

        self.identity = generate_site_identity(sector="water", seed="proto-test-01")
        self.profile = WaterProfile(self.identity, noise_amplitude=0.0)
        self.state_engine = StateEngine(self.identity, self.profile, tick_interval=0.1)
        self.state_engine.start()

        self.port = 15502
        self.server = ModbusServer(
            host="127.0.0.1",
            port=self.port,
            unit_id=1,
            state_engine=self.state_engine,
            identity=self.identity,
            event_logger=self.logger,
            response_delay_ms=0,
            allow_broadcast=True,
        )
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        self.state_engine.stop()
        self.logger.close()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_frame_read_holding_registers(self):
        """Read valid mapped holding register."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        hr_tag = self.identity.tags["LEVEL_SETPOINT_PCT"]
        hr_addr = hr_tag.address

        mbap = struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, 0x01)
        pdu = struct.pack(">BHH", ModbusFunction.READ_HOLDING_REGISTERS, hr_addr, 1)
        writer.write(mbap + pdu)
        await writer.drain()

        resp_hdr = await reader.readexactly(7)
        resp_len = struct.unpack(">HHHB", resp_hdr)[2]
        resp_pdu = await reader.readexactly(resp_len - 1)

        fc = resp_pdu[0]
        self.assertEqual(fc, ModbusFunction.READ_HOLDING_REGISTERS)

        writer.close()
        await writer.wait_closed()

    async def test_unmapped_address_returns_modbus_exception_02(self):
        """Scanners querying unmapped registers must receive ILLEGAL_DATA_ADDRESS (0x02)."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        mbap = struct.pack(">HHHB", 0x0002, 0x0000, 0x0006, 0x01)
        pdu = struct.pack(">BHH", ModbusFunction.READ_HOLDING_REGISTERS, 5000, 5)
        writer.write(mbap + pdu)
        await writer.drain()

        resp_hdr = await reader.readexactly(7)
        resp_len = struct.unpack(">HHHB", resp_hdr)[2]
        resp_pdu = await reader.readexactly(resp_len - 1)

        self.assertEqual(resp_pdu[0], ModbusFunction.READ_HOLDING_REGISTERS | 0x80)
        self.assertEqual(resp_pdu[1], ModbusException.ILLEGAL_DATA_ADDRESS)

        writer.close()
        await writer.wait_closed()

    async def test_invalid_coil_value_returns_modbus_exception_03(self):
        """Writing invalid coil value (not 0x0000 or 0xFF00) must return ILLEGAL_DATA_VALUE (0x03)."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        coil_tag = self.identity.tags["PUMP_1_CMD"]
        coil_addr = coil_tag.address

        mbap = struct.pack(">HHHB", 0x0003, 0x0000, 0x0006, 0x01)
        pdu = struct.pack(">BHH", ModbusFunction.WRITE_SINGLE_COIL, coil_addr, 0x1234)
        writer.write(mbap + pdu)
        await writer.drain()

        resp_hdr = await reader.readexactly(7)
        resp_len = struct.unpack(">HHHB", resp_hdr)[2]
        resp_pdu = await reader.readexactly(resp_len - 1)

        self.assertEqual(resp_pdu[0], ModbusFunction.WRITE_SINGLE_COIL | 0x80)
        self.assertEqual(resp_pdu[1], ModbusException.ILLEGAL_DATA_VALUE)

        writer.close()
        await writer.wait_closed()

    async def test_unit_zero_broadcast_reads_full_pdu_without_stream_desync(self):
        """Unit 0 broadcast write must consume PDU and allow subsequent frames without desynchronization."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        coil_tag = self.identity.tags["PUMP_1_CMD"]
        coil_addr = coil_tag.address

        # Send broadcast write (unit_id = 0)
        mbap_bcast = struct.pack(">HHHB", 0x0010, 0x0000, 0x0006, 0x00)
        pdu_bcast = struct.pack(">BHH", ModbusFunction.WRITE_SINGLE_COIL, coil_addr, 0xFF00)
        writer.write(mbap_bcast + pdu_bcast)
        await writer.drain()

        # Follow up immediately on SAME TCP connection with regular unicast read (unit_id = 1)
        hr_tag = self.identity.tags["LEVEL_SETPOINT_PCT"]
        mbap_read = struct.pack(">HHHB", 0x0011, 0x0000, 0x0006, 0x01)
        pdu_read = struct.pack(">BHH", ModbusFunction.READ_HOLDING_REGISTERS, hr_tag.address, 1)
        writer.write(mbap_read + pdu_read)
        await writer.drain()

        # Read response for the unicast read
        resp_hdr = await reader.readexactly(7)
        resp_trans, _, resp_len, resp_unit = struct.unpack(">HHHB", resp_hdr)
        self.assertEqual(resp_trans, 0x0011, "Transaction ID must match subsequent request")
        self.assertEqual(resp_unit, 0x01)

        resp_pdu = await reader.readexactly(resp_len - 1)
        self.assertEqual(resp_pdu[0], ModbusFunction.READ_HOLDING_REGISTERS)

        writer.close()
        await writer.wait_closed()

    async def test_device_identification_mei(self):
        """Read Device Identification (0x2B / 0x0E) must return standard MEI objects."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        mbap = struct.pack(">HHHB", 0x0004, 0x0000, 0x0005, 0x01)
        pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
        writer.write(mbap + pdu)
        await writer.drain()

        resp_hdr = await reader.readexactly(7)
        resp_len = struct.unpack(">HHHB", resp_hdr)[2]
        resp_pdu = await reader.readexactly(resp_len - 1)

        self.assertEqual(resp_pdu[0], 0x2B)
        self.assertEqual(resp_pdu[1], 0x0E)
        self.assertTrue(self.identity.vendor.encode("utf-8") in resp_pdu)

        writer.close()
        await writer.wait_closed()

    async def _read_holding(self, reader, writer) -> int:
        addr = self.identity.tags["LEVEL_SETPOINT_PCT"].address
        writer.write(struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, 0x01)
                     + struct.pack(">BHH", ModbusFunction.READ_HOLDING_REGISTERS, addr, 1))
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(7), 2.0)
        pdu = await asyncio.wait_for(reader.readexactly(struct.unpack(">HHHB", hdr)[2] - 1), 2.0)
        return pdu[0]

    async def test_connections_beyond_the_per_address_limit_are_refused(self):
        """One address can't hold more than its share of connections; a freed slot is reusable."""
        self.server.max_clients_per_ip = 2
        conns = [await asyncio.open_connection("127.0.0.1", self.port) for _ in range(2)]
        await asyncio.sleep(0.1)                      # let the server register both

        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2.0), b"", "the third connection must be closed")
        writer.close()

        for r, w in conns:                            # the accepted ones still work
            self.assertEqual(await self._read_holding(r, w), ModbusFunction.READ_HOLDING_REGISTERS)

        conns[0][1].close()
        await conns[0][1].wait_closed()
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.assertEqual(await self._read_holding(reader, writer), ModbusFunction.READ_HOLDING_REGISTERS,
                         "a slot freed by a closed connection must be usable again")
        for _, w in [conns[1], (reader, writer)]:
            w.close()

    async def test_overall_connection_limit(self):
        self.server.max_clients = 1
        r1, w1 = await asyncio.open_connection("127.0.0.1", self.port)
        await asyncio.sleep(0.1)
        r2, w2 = await asyncio.open_connection("127.0.0.1", self.port)
        self.assertEqual(await asyncio.wait_for(r2.read(1), 2.0), b"")
        self.assertEqual(await self._read_holding(r1, w1), ModbusFunction.READ_HOLDING_REGISTERS)
        w1.close()
        w2.close()

    async def test_silent_connection_is_closed_after_the_idle_timeout(self):
        self.server.idle_timeout_s = 0.3
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3.0), b"", "an idle connection must be closed")
        writer.close()


if __name__ == "__main__":
    unittest.main()
