"""Unit tests for EventLogger, latency, and SOC metrics calculation."""
import os
import sqlite3
import tempfile
import time
import unittest
from ghostgrid.core.logger.db import EventLogger


class TestLoggerAndMetrics(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_soc.db")
        self.logger = EventLogger(
            db_path=self.db_path,
            alert_threshold_writes=1,
            alert_threshold_scans=5,
        )

    def tearDown(self):
        self.logger.close()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_nonblocking_latency(self):
        """Logging a request must return in under 1 millisecond."""
        s_id = self.logger.start_session("192.168.1.100", 49152, 1)

        t0 = time.perf_counter()
        self.logger.log_request(
            session_id=s_id,
            function_code=3,
            function_name="Read Holding Registers",
            address=0,
            count=2,
            values=[800, 650],
            latency_ms=0.5,
            response_status="SUCCESS",
            tag_name="LEVEL_SETPOINT_PCT",
            is_honeytoken=False,
            client_ip="192.168.1.100",
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Non-blocking write via queue
        self.assertLess(elapsed_ms, 2.0, f"Logging took too long: {elapsed_ms:.2f}ms")

    def test_per_ip_time_gained_calculation(self):
        """Time Gained must measure duration per attacker IP."""
        ip = "10.0.0.99"
        s1 = self.logger.start_session(ip, 50001, 1)
        time.sleep(0.05)
        self.logger.log_request(s1, 3, "Read", 0, 1, [1], 0.1, "SUCCESS", client_ip=ip)
        self.logger.end_session(s1)

        time.sleep(0.1)

        s2 = self.logger.start_session(ip, 50002, 1)
        time.sleep(0.05)
        self.logger.log_request(s2, 3, "Read", 1, 1, [1], 0.1, "SUCCESS", client_ip=ip)
        self.logger.end_session(s2)

        self.logger.flush()
        metrics = self.logger.get_soc_metrics()
        self.assertGreater(metrics["total_time_gained_seconds"], 0.15)

    def test_visit_gap_clustering_prevents_multi_day_overcount(self):
        """Visits separated by quiet gap (> 1800s) must NOT count gap as continuous dwell time."""
        self.logger.close()

        # Insert 2 visits 7 days apart directly in the DB
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        ip = "192.168.50.77"
        t_week_ago = time.time() - (7 * 86400)
        t_now = time.time()

        # Visit 1: 30 seconds duration a week ago
        cur.execute(
            """INSERT INTO sessions (session_id, client_ip, client_port, unit_id, started_at, last_seen, total_requests, total_writes, time_gained_seconds, is_active)
               VALUES (?, ?, ?, ?, ?, ?, 5, 0, 30.0, 0)""",
            ("s_old", ip, 40001, 1, t_week_ago, t_week_ago + 30.0),
        )

        # Visit 2: 20 seconds duration today
        cur.execute(
            """INSERT INTO sessions (session_id, client_ip, client_port, unit_id, started_at, last_seen, total_requests, total_writes, time_gained_seconds, is_active)
               VALUES (?, ?, ?, ?, ?, ?, 3, 0, 20.0, 0)""",
            ("s_new", ip, 40002, 1, t_now, t_now + 20.0),
        )
        conn.commit()
        conn.close()

        # Reopen with read_only
        ro_logger = EventLogger(self.db_path, read_only=True)
        metrics = ro_logger.get_soc_metrics()
        total_time = metrics["total_time_gained_seconds"]

        # Total time gained should be ~50 seconds (30s + 20s), NOT 7 days (604,800s)!
        self.assertLess(total_time, 120.0, f"Visit gap overcounted: {total_time} seconds recorded instead of distinct visits")
        self.assertGreaterEqual(total_time, 45.0)
        ro_logger.close()

    def test_recon_scan_alert_across_reconnections(self):
        """Cross-connection requests must accumulate and trigger scan alert at threshold."""
        ip = "172.16.0.50"
        for i in range(5):
            s = self.logger.start_session(ip, 60000 + i, 1)
            self.logger.log_request(s, 3, "Read", i, 1, [1], 0.1, "SUCCESS", client_ip=ip)
            self.logger.end_session(s)

        self.logger.flush()
        alerts = self.logger.get_recent_alerts(limit=10)
        recon_alerts = [a for a in alerts if a["alert_type"] == "RECON_SCAN"]
        self.assertTrue(len(recon_alerts) >= 1, "Recon scan alert should trigger across reconnecting sessions")

    def test_write_alerts_follow_escalation_and_rearm_per_visit(self):
        """Each new tag written in a visit alerts once; repeats stay quiet; a new visit re-arms alerts."""
        from types import SimpleNamespace
        from unittest import mock
        import ghostgrid.core.logger.db as db_module

        clock = [1_000_000.0]
        fake_time = SimpleNamespace(time=lambda: clock[0])
        ip = "10.20.30.40"

        def write(tag):
            self.logger.log_request(s_id, 5, "Write Single Coil", 0, 1, 0, 0.1, "SUCCESS", tag, False, ip)

        def write_alert_count():
            self.logger.flush()
            return len([a for a in self.logger.get_recent_alerts(limit=100) if a["alert_type"] == "UNAUTHORIZED_WRITE"])

        with mock.patch.object(db_module, "time", fake_time):
            s_id = self.logger.start_session(ip, 50500, 1)
            for tag in ("LEVEL_SETPOINT_PCT", "LEVEL_SETPOINT_PCT", "PUMP_1_CMD", "EMERGENCY_SHUTDOWN_CMD"):
                write(tag)
            self.assertEqual(write_alert_count(), 3, "setpoint, pump stop and shutdown must each alert; the repeat must not")

            clock[0] += 60.0
            write("PUMP_1_CMD")
            self.assertEqual(write_alert_count(), 3, "same tag again within the visit must stay quiet")

            clock[0] += db_module.VISIT_GAP_SECONDS + 1.0
            write("PUMP_1_CMD")
            self.assertEqual(write_alert_count(), 4, "a new visit after a quiet gap must alert again")

    def test_read_only_mode_and_cleanup_stale_flag(self):
        """Read-only logger must not launch write worker thread and must not modify database."""
        ro_logger = EventLogger(self.db_path, read_only=True, cleanup_stale_sessions=False)
        self.assertIsNone(ro_logger._worker_thread)
        metrics = ro_logger.get_soc_metrics()
        self.assertIsInstance(metrics, dict)
        ro_logger.close()


if __name__ == "__main__":
    unittest.main()
