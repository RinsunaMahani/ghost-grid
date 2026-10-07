"""Alerts reach the SOC's SIEM: a JSON Lines file, and syslog over UDP as JSON or CEF."""
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

from ghostgrid.config import load_config
from ghostgrid.core.logger import EventLogger
from ghostgrid.core.logger.forward import AlertForwarder, to_cef

IP = "10.20.30.40"


def _visit(logger):
    """A connection that reads one honeytoken: FIRST_CONTACT (HIGH), then HONEYTOKEN_TRIGGER (CRITICAL)."""
    sid = logger.start_session(IP, 50123, 1)
    logger.log_request(sid, 3, "Read Holding Registers", 40100, 1, [4660], 0.2, "SUCCESS",
                       "BACKDOOR_CALIBRATION_KEY", True, IP)
    logger.flush()
    return sid


class TestAlertForwarding(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "soc.db")

    def _collector(self):
        """A UDP socket standing in for the SIEM's syslog collector."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(3.0)
        self.addCleanup(sock.close)
        return sock

    @staticmethod
    def _receive(sock, count):
        return [sock.recvfrom(65535)[0].decode("utf-8") for _ in range(count)]

    def test_alerts_are_appended_to_a_jsonl_file(self):
        path = os.path.join(self.tmp.name, "alerts.jsonl")
        logger = EventLogger(self.db, alert_forwarder=AlertForwarder(jsonl_path=path, decoy_name="decoy-01"))
        sid = _visit(logger)
        logger.close()

        with open(path, encoding="utf-8") as f:
            records = [json.loads(line) for line in f]
        self.assertEqual([r["alert_type"] for r in records], ["FIRST_CONTACT", "HONEYTOKEN_TRIGGER"])
        honeytoken = records[1]
        self.assertEqual((honeytoken["src_ip"], honeytoken["src_port"], honeytoken["session_id"], honeytoken["decoy"]),
                         (IP, 50123, sid, "decoy-01"))
        self.assertEqual(honeytoken["mitre_technique"], "T0861: Point & Tag Identification")
        self.assertTrue(honeytoken["time"].endswith("Z"), "times are UTC, ISO 8601")

    def test_alerts_reach_a_syslog_collector_as_rfc5424_json(self):
        collector = self._collector()
        logger = EventLogger(self.db, alert_forwarder=AlertForwarder(
            syslog_host="127.0.0.1", syslog_port=collector.getsockname()[1], decoy_name="decoy-01"))
        _visit(logger)
        logger.close()

        first, second = self._receive(collector, 2)
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        parts = first.split(" ", 7)
        self.assertEqual(parts[0], "<131>1", "facility local0, severity error for a HIGH alert")
        self.assertEqual(parts[2:7], ["decoy-01", "ghostgrid", "-", "FIRST_CONTACT", "-"])
        self.assertEqual(json.loads(parts[7])["src_ip"], IP)
        parts = second.split(" ", 7)
        self.assertEqual(parts[0], "<130>1", "severity critical for a CRITICAL alert")
        self.assertEqual(parts[5], "HONEYTOKEN_TRIGGER")

    def test_cef_output_for_siems_that_read_it_natively(self):
        collector = self._collector()
        logger = EventLogger(self.db, alert_forwarder=AlertForwarder(
            syslog_host="127.0.0.1", syslog_port=collector.getsockname()[1], syslog_format="cef",
            decoy_name="decoy-01"))
        _visit(logger)
        logger.close()

        cef = self._receive(collector, 2)[1].split(" ", 7)[7]
        self.assertTrue(cef.startswith("CEF:0|GhostGrid|OT Decoy|0.1.0|HONEYTOKEN_TRIGGER|Honeytoken Trigger|10|"), cef)
        for field in (f"src={IP}", "spt=50123", "dvchost=decoy-01", "cs1=T0861: Point & Tag Identification"):
            self.assertIn(field, cef)

    def test_cef_escapes_its_separators(self):
        cef = to_cef({"timestamp": 1.0, "severity": "MEDIUM", "alert_type": "A|B", "mitre_technique": "x=y",
                      "session_id": "s", "description": "line1\nline2 \\ =", "client_ip": "1.2.3.4",
                      "client_port": 1})
        self.assertIn("|A\\|B|", cef, "a pipe in a header field must be escaped")
        self.assertIn("cs1=x\\=y", cef, "an equals sign in an extension value must be escaped")
        self.assertIn("msg=line1\\nline2 \\\\ \\=", cef, "newlines and backslashes must be escaped")

    def test_broken_outputs_never_stop_alerts_being_recorded(self):
        forwarder = AlertForwarder(jsonl_path=os.path.join(self.tmp.name, "no-such-dir", "alerts.jsonl"),
                                   syslog_host="collector.invalid")
        logger = EventLogger(self.db, alert_forwarder=forwarder)
        with self.assertLogs("ghostgrid.forward", level="WARNING") as logs:
            _visit(logger)
            _visit(logger)
        self.assertEqual(len(logger.get_recent_alerts(limit=10)), 4, "every alert must still reach the database")
        self.assertEqual(len(logs.records), 2, "each problem is reported once, not once per alert")
        logger.close()

    def test_no_forwarding_unless_configured(self):
        self.assertFalse(AlertForwarder().enabled)
        with self.assertRaises(ValueError):
            AlertForwarder(syslog_host="127.0.0.1", syslog_format="xml")

    def test_settings_come_from_the_environment_too(self):
        with mock.patch.dict(os.environ, {"GHOSTGRID_SYSLOG_HOST": "10.1.1.5", "GHOSTGRID_SYSLOG_FORMAT": "CEF",
                                          "GHOSTGRID_ALERTS_JSONL": "/data/alerts.jsonl"}):
            cfg = load_config()
        self.assertEqual((cfg.logging.syslog_host, cfg.logging.syslog_port, cfg.logging.syslog_format,
                          cfg.logging.alerts_jsonl_path), ("10.1.1.5", 514, "cef", "/data/alerts.jsonl"))


if __name__ == "__main__":
    unittest.main()
