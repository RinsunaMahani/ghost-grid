"""Lifecycle integration tests for the GhostGrid decoy process."""
import asyncio
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from ghostgrid.core.protocol.frames import ModbusFunction
from ghostgrid.core.logger.db import EventLogger


class TestDecoyLifecycle(unittest.TestCase):

    def test_run_decoy_startup_and_modbus_handshake(self):
        """Spawns run_decoy in a subprocess, queries Modbus TCP, and terminates cleanly."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = os.path.join(tmp_dir, "lifecycle_soc.db")
            state_path = os.path.join(tmp_dir, "lifecycle_state.json")
            id_path = os.path.join(tmp_dir, "lifecycle_identity.json")

            port = 15588
            env = os.environ.copy()
            env["GHOSTGRID_DB_PATH"] = db_path
            env["GHOSTGRID_STATE_PATH"] = state_path
            env["GHOSTGRID_IDENTITY_PATH"] = id_path
            env["MODBUS_HOST"] = "127.0.0.1"  # keep the test decoy off the network

            # Launch decoy process via python -m ghostgrid.run_decoy
            cmd = [
                sys.executable,
                "-m",
                "ghostgrid.run_decoy",
                "--sector",
                "water",
                "--port",
                str(port),
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )

            try:
                # Wait up to 5 seconds for Modbus TCP socket to open
                connected = False
                for _ in range(50):
                    time.sleep(0.1)
                    if proc.poll() is not None:
                        # Process died prematurely!
                        stdout, stderr = proc.communicate()
                        self.fail(f"Decoy process exited unexpectedly with code {proc.returncode}.\nSTDOUT: {stdout}\nSTDERR: {stderr}")

                    # Attempt socket connection
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    try:
                        s.connect(("127.0.0.1", port))
                        connected = True

                        # Send Modbus FC 0x03 read
                        mbap = struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, 0x01)
                        pdu = struct.pack(">BHH", ModbusFunction.READ_HOLDING_REGISTERS, 0, 1)
                        s.sendall(mbap + pdu)
                        resp = s.recv(1024)
                        self.assertGreater(len(resp), 7, "Modbus response must include MBAP header and PDU")
                        s.close()
                        break
                    except (ConnectionRefusedError, socket.timeout):
                        s.close()

                self.assertTrue(connected, "Failed to connect to decoy Modbus TCP server within 5 seconds")

                # Verify files were created
                self.assertTrue(os.path.exists(id_path), "Identity file must be generated")

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)

    def test_unauthorized_write_alert_threshold_noise_reduction(self):
        """Write alerts must NOT fire on every write; they only fire when threshold is reached."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = os.path.join(tmp_dir, "noise_test.db")
            # Threshold set to 3 writes before alerting
            logger = EventLogger(
                db_path=db_path,
                alert_threshold_writes=3,
                alert_threshold_scans=10,
                honeytoken_registers=[40099],
            )

            client_ip = "192.168.10.150"
            s_id = logger.start_session(client_ip, 50123, 1)

            # Write 1: Below threshold of 3 -> NO alert
            logger.log_request(
                session_id=s_id,
                function_code=6,
                function_name="Write Single Register",
                address=10,
                count=1,
                values=[850],
                latency_ms=0.2,
                response_status="SUCCESS",
                tag_name="LEVEL_SETPOINT_PCT",
                is_honeytoken=False,
                client_ip=client_ip,
            )
            logger.flush()
            alerts = logger.get_recent_alerts(limit=10)
            write_alerts = [a for a in alerts if a["alert_type"] == "UNAUTHORIZED_WRITE"]
            self.assertEqual(len(write_alerts), 0, "Single write below threshold should not raise an unauthorized write alert")

            # Write 2: Still below threshold of 3 -> NO alert
            logger.log_request(
                session_id=s_id,
                function_code=6,
                function_name="Write Single Register",
                address=10,
                count=1,
                values=[860],
                latency_ms=0.2,
                response_status="SUCCESS",
                tag_name="LEVEL_SETPOINT_PCT",
                is_honeytoken=False,
                client_ip=client_ip,
            )
            logger.flush()
            alerts = logger.get_recent_alerts(limit=10)
            write_alerts = [a for a in alerts if a["alert_type"] == "UNAUTHORIZED_WRITE"]
            self.assertEqual(len(write_alerts), 0, "Second write below threshold should not raise an unauthorized write alert")

            # Write 3: Reaches threshold of 3 -> EXACTLY 1 alert raised
            logger.log_request(
                session_id=s_id,
                function_code=6,
                function_name="Write Single Register",
                address=10,
                count=1,
                values=[870],
                latency_ms=0.2,
                response_status="SUCCESS",
                tag_name="LEVEL_SETPOINT_PCT",
                is_honeytoken=False,
                client_ip=client_ip,
            )
            logger.flush()
            alerts = logger.get_recent_alerts(limit=10)
            write_alerts = [a for a in alerts if a["alert_type"] == "UNAUTHORIZED_WRITE"]
            self.assertEqual(len(write_alerts), 1, "Reaching write threshold must trigger exactly 1 unauthorized write alert (no duplicate)")
            self.assertEqual(write_alerts[0]["alert_type"], "UNAUTHORIZED_WRITE")

            logger.close()

    def test_database_connection_closes_immediately_on_windows(self):
        """Querying metrics must not leak open file handles on Windows, allowing clean file deletion."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = os.path.join(tmp_dir, "handle_test.db")
            logger = EventLogger(db_path=db_path)
            s_id = logger.start_session("10.0.0.1", 50000, 1)
            logger.flush()
            metrics = logger.get_soc_metrics()
            self.assertIsInstance(metrics, dict)
            logger.close()

            # On Windows, if sqlite connections were not closed, removing the file raises WinError 32
            try:
                os.remove(db_path)
            except PermissionError as e:
                self.fail(f"Database connection handle leaked on Windows: {e}")


if __name__ == "__main__":
    unittest.main()
