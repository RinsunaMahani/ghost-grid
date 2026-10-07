"""Forwarding GhostGrid alerts to the SOC's own tools as they happen.

The console is one way to see alerts, but a SOC works in its SIEM. Two optional outputs:

- a JSON Lines file, one alert per line, for a log shipper (Filebeat, Wazuh agent, Fluent Bit);
- syslog over UDP (RFC 5424) straight to a collector, carrying the alert as JSON or as CEF, the
  Common Event Format that most SIEMs parse natively.

UDP syslog only ever sends: the decoy never listens for a reply. So it can cross a one-way data
diode into the SOC network without giving a visitor on the OT side any path back.

Forwarding must never break the decoy. A full disk or an unreachable collector is reported once
in the decoy's log and otherwise ignored; the SQLite record is always the primary copy.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("ghostgrid.forward")

# RFC 5424 severities and CEF severities (0-10) for GhostGrid's alert levels.
SYSLOG_SEVERITY = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5}
CEF_SEVERITY = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}
FACILITY_LOCAL0 = 16
CEF_VENDOR, CEF_PRODUCT, CEF_VERSION = "GhostGrid", "OT Decoy", "0.1.0"
RESOLVE_RETRY_SECONDS = 60.0


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _syslog_hostname(name: str) -> str:
    """RFC 5424 HOSTNAME: printable ASCII without spaces, at most 255 characters."""
    clean = re.sub(r"[^!-~]", "-", name or "")[:255]
    return clean or "-"


def to_record(alert: Dict[str, Any]) -> Dict[str, Any]:
    """One alert as a flat JSON object, the same fields for every output."""
    return {
        "time": _iso(alert["timestamp"]),
        "decoy": alert.get("decoy"),
        "severity": alert["severity"],
        "alert_type": alert["alert_type"],
        "mitre_technique": alert["mitre_technique"],
        "src_ip": alert.get("client_ip"),
        "src_port": alert.get("client_port"),
        "session_id": alert["session_id"],
        "description": alert["description"],
    }


def _cef_header(text: Any) -> str:
    return str(text).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(text: Any) -> str:
    return (str(text).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def to_cef(alert: Dict[str, Any]) -> str:
    """One alert as a CEF record: header fields escape | and \\, extension values escape = and \\."""
    extension = {
        "rt": int(alert["timestamp"] * 1000),
        "src": alert.get("client_ip"),
        "spt": alert.get("client_port"),
        "dvchost": alert.get("decoy"),
        "cs1Label": "mitreTechnique",
        "cs1": alert["mitre_technique"],
        "cs2Label": "sessionId",
        "cs2": alert["session_id"],
        "msg": alert["description"],
    }
    ext = " ".join(f"{key}={_cef_value(value)}" for key, value in extension.items()
                   if value is not None and value != "")
    name = alert["alert_type"].replace("_", " ").title()
    return (f"CEF:0|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_VERSION}|{_cef_header(alert['alert_type'])}|"
            f"{_cef_header(name)}|{CEF_SEVERITY.get(alert['severity'], 5)}|{ext}")


def to_syslog(alert: Dict[str, Any], body: str, hostname: str) -> bytes:
    """An RFC 5424 message: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG."""
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(alert["severity"], 5)
    msgid = re.sub(r"[^!-~]", "_", alert["alert_type"])[:32] or "-"
    return f"<{pri}>1 {_iso(alert['timestamp'])} {hostname} ghostgrid - {msgid} - {body}".encode("utf-8")


class AlertForwarder:
    """Sends each committed alert to the configured outputs. Called only from the logger's writer thread."""

    def __init__(
        self,
        jsonl_path: Optional[str] = None,
        syslog_host: Optional[str] = None,
        syslog_port: int = 514,
        syslog_format: str = "json",
        decoy_name: Optional[str] = None,
    ):
        if syslog_format not in ("json", "cef"):
            raise ValueError(f"syslog_format must be 'json' or 'cef', not {syslog_format!r}")
        self.jsonl_path = jsonl_path or None
        self.syslog_host = syslog_host or None
        self.syslog_port = int(syslog_port)
        self.syslog_format = syslog_format
        self.decoy_name = _syslog_hostname(decoy_name or socket.gethostname())
        self._sock: Optional[socket.socket] = None
        self._target: Optional[Tuple[Any, ...]] = None
        self._resolve_after = 0.0
        self._warned: set = set()

    @property
    def enabled(self) -> bool:
        return bool(self.jsonl_path or self.syslog_host)

    def describe(self) -> str:
        parts = []
        if self.syslog_host:
            parts.append(f"syslog {self.syslog_host}:{self.syslog_port} ({self.syslog_format})")
        if self.jsonl_path:
            parts.append(f"file {self.jsonl_path}")
        return ", ".join(parts) or "off"

    def forward(self, alert: Dict[str, Any]) -> None:
        alert = dict(alert, decoy=self.decoy_name)
        record = to_record(alert)
        if self.jsonl_path:
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError as e:
                self._warn_once("jsonl", "Can't append alerts to %s: %s", self.jsonl_path, e)
        if self.syslog_host:
            target = self._syslog_target()
            if target is not None:
                body = to_cef(alert) if self.syslog_format == "cef" else json.dumps(record, ensure_ascii=False)
                try:
                    self._sock.sendto(to_syslog(alert, body, self.decoy_name), target)
                except OSError as e:
                    self._warn_once("send", "Can't send alerts to syslog %s:%s: %s",
                                    self.syslog_host, self.syslog_port, e)

    def _syslog_target(self) -> Optional[Tuple[Any, ...]]:
        """Resolve the collector once; if that fails (DNS not up yet), retry at most once a minute."""
        if self._target is None and time.monotonic() >= self._resolve_after:
            try:
                family, _, _, _, address = socket.getaddrinfo(
                    self.syslog_host, self.syslog_port, type=socket.SOCK_DGRAM)[0]
                self._sock = socket.socket(family, socket.SOCK_DGRAM)
                self._target = address
            except OSError as e:
                self._resolve_after = time.monotonic() + RESOLVE_RETRY_SECONDS
                self._warn_once("resolve", "Can't resolve syslog collector %s: %s (retrying every %.0f s)",
                                self.syslog_host, e, RESOLVE_RETRY_SECONDS)
        return self._target

    def _warn_once(self, key: str, message: str, *args: Any) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
