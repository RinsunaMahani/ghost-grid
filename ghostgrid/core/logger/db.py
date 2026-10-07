"""SQLite Logger and Incident Tracking for GhostGrid.

Tracks incoming connections, Modbus requests/responses, latency, attacker writes,
and honeytoken interactions.
Features:
- Background writer thread with batched commits: Modbus responses never wait on SQLite writes (<1ms).
- Per-IP visit-based Time Gained: groups sessions into visits with a 30-minute quiet gap cutoff.
- Startup stale session cleanup runs ONLY in decoy, never in dashboard.
- Read-only mode for dashboard so it never fails on read-only Docker mounts or closes decoy sessions.
- Per-visit alerting: one scan alert per IP per visit, and one write alert for each new tag
  an IP writes to during a visit, so escalation (setpoint -> pump stop -> shutdown) is never hidden.
"""
import contextlib
import json
import logging
import os
import queue
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple

from ghostgrid.core.logger.forward import AlertForwarder

logger = logging.getLogger("ghostgrid.logger")

# A visit ends after this much silence from an IP. Used for Time Gained and for re-arming alerts.
VISIT_GAP_SECONDS = 1800.0


@dataclass
class Alert:
    id: Optional[int]
    session_id: str
    timestamp: float
    severity: str
    alert_type: str
    mitre_technique: str
    description: str


@dataclass
class SessionRecord:
    session_id: str
    client_ip: str
    client_port: int
    unit_id: int
    started_at: float
    last_seen: float
    total_requests: int
    total_writes: int
    time_gained_seconds: float
    is_active: bool
    notes: str = ""


@dataclass
class RequestRecord:
    id: Optional[int]
    session_id: str
    timestamp: float
    function_code: int
    function_name: str
    address: int
    count: int
    values_json: str
    latency_ms: float
    response_status: str
    tag_name: Optional[str] = None
    is_honeytoken: bool = False


class EventLogger:
    """Non-blocking SQLite logger with background worker thread and read-only support."""

    def __init__(
        self,
        db_path: str = "ghostgrid_soc.db",
        alert_threshold_writes: int = 1,
        alert_threshold_scans: int = 10,
        honeytoken_registers: Optional[List[int]] = None,
        read_only: bool = False,
        cleanup_stale_sessions: bool = False,
        alert_forwarder: Optional[AlertForwarder] = None,
    ):
        self.db_path = db_path
        self.alert_threshold_writes = alert_threshold_writes
        self.alert_threshold_scans = alert_threshold_scans
        self.honeytoken_registers = honeytoken_registers or [40099, 40100, 40101]
        self.read_only = read_only
        self.cleanup_stale_sessions = cleanup_stale_sessions
        # Sends each alert to the SOC's SIEM once it is committed; never used in read-only mode.
        self.alert_forwarder = None if read_only else alert_forwarder

        # Per-IP alert state for the current visit, kept across reconnections
        self._visits: Dict[str, Dict[str, Any]] = {}
        self._visits_swept_at = 0.0

        self._queue: queue.Queue = queue.Queue()
        self._running = not read_only

        if not read_only:
            self._init_db()
            self._worker_thread = threading.Thread(
                target=self._batch_writer_loop,
                daemon=True,
                name="GhostGrid-DBWriter",
            )
            self._worker_thread.start()
        else:
            self._worker_thread = None

    @contextlib.contextmanager
    def _get_connection(self):
        # Context manager providing an active SQLite connection that is guaranteed to close on exit.
        if self.read_only:
            if os.path.exists(self.db_path):
                uri_path = f"file:{os.path.abspath(self.db_path)}?mode=ro"
                conn = sqlite3.connect(uri_path, uri=True, timeout=10.0)
            else:
                conn = sqlite3.connect(":memory:")
        else:
            conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _create_raw_connection(self) -> sqlite3.Connection:
        # Create a persistent connection dedicated to the background batch writer thread.
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema, indexes, and close any stale sessions if configured."""
        if self.read_only:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    client_ip TEXT NOT NULL,
                    client_port INTEGER NOT NULL,
                    unit_id INTEGER NOT NULL,
                    started_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    total_requests INTEGER DEFAULT 0,
                    total_writes INTEGER DEFAULT 0,
                    time_gained_seconds REAL DEFAULT 0.0,
                    is_active INTEGER DEFAULT 1,
                    notes TEXT DEFAULT ''
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    function_code INTEGER NOT NULL,
                    function_name TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    count INTEGER NOT NULL,
                    values_json TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    response_status TEXT NOT NULL,
                    tag_name TEXT,
                    is_honeytoken INTEGER DEFAULT 0,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    severity TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    mitre_technique TEXT NOT NULL,
                    description TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS storylines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    title TEXT NOT NULL,
                    narrative TEXT NOT NULL,
                    adjustments_json TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_client_ip ON sessions(client_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_lastseen ON sessions(last_seen)")

            # Clean up stale active sessions ONLY when explicitly requested (in decoy, NEVER dashboard)
            if self.cleanup_stale_sessions:
                cursor.execute("""
                    UPDATE sessions
                    SET is_active = 0,
                        time_gained_seconds = MAX(0.0, last_seen - started_at),
                        notes = CASE WHEN notes = '' THEN 'Cleaned up at startup' ELSE notes END
                    WHERE is_active = 1
                """)
            conn.commit()

    def _batch_writer_loop(self):
        """Dedicated background thread executing batched SQLite transactions."""
        conn = self._create_raw_connection()
        peers: Dict[str, Tuple[str, int]] = {}    # session -> (client ip, port), for forwarded alerts
        outgoing: List[Dict[str, Any]] = []        # alerts to forward once the current batch is committed

        def raise_alert(cursor, s_id, now, severity, alert_type, mitre, description):
            cursor.execute("""
                INSERT INTO alerts (session_id, timestamp, severity, alert_type, mitre_technique, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (s_id, now, severity, alert_type, mitre, description))
            if self.alert_forwarder is None:
                return
            if s_id not in peers:                  # a session from before a restart: look it up
                row = cursor.execute("SELECT client_ip, client_port FROM sessions WHERE session_id = ?",
                                     (s_id,)).fetchone()
                peers[s_id] = (row["client_ip"], row["client_port"]) if row else (None, None)
            ip, port = peers[s_id]
            outgoing.append({"session_id": s_id, "timestamp": now, "severity": severity,
                             "alert_type": alert_type, "mitre_technique": mitre,
                             "description": description, "client_ip": ip, "client_port": port})

        while self._running or not self._queue.empty():
            items = []
            outgoing.clear()
            try:
                first = self._queue.get(timeout=0.2)
                items.append(first)
                while len(items) < 50:
                    try:
                        items.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if not items:
                continue

            try:
                cursor = conn.cursor()
                for action, payload in items:
                    if action == "start_session":
                        s_id, ip, port, uid, now = payload
                        cursor.execute("""
                            INSERT INTO sessions (
                                session_id, client_ip, client_port, unit_id, started_at, last_seen,
                                total_requests, total_writes, time_gained_seconds, is_active
                            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0.0, 1)
                        """, (s_id, ip, port, uid, now, now))
                        peers[s_id] = (ip, port)
                        raise_alert(
                            cursor, s_id, now, "HIGH", "FIRST_CONTACT", "T0846: Remote System Discovery",
                            f"Unauthorized Modbus TCP connection initiated from {ip}:{port} to Unit ID {uid}."
                        )

                    elif action == "log_request":
                        s_id, now, fc, fname, addr, cnt, vals_str, lat, status, tag, is_ht, is_wr = payload
                        cursor.execute("""
                            INSERT INTO requests (
                                session_id, timestamp, function_code, function_name, address, count,
                                values_json, latency_ms, response_status, tag_name, is_honeytoken
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (s_id, now, fc, fname, addr, cnt, vals_str, lat, status, tag, 1 if is_ht else 0))

                        cursor.execute("""
                            UPDATE sessions
                            SET last_seen = ?,
                                total_requests = total_requests + 1,
                                total_writes = total_writes + ?,
                                time_gained_seconds = (? - started_at)
                            WHERE session_id = ?
                        """, (now, 1 if is_wr else 0, now, s_id))

                        if is_ht:
                            raise_alert(
                                cursor, s_id, now, "CRITICAL", "HONEYTOKEN_TRIGGER",
                                # A read maps the plant's points; a write changes one.
                                "T0836: Modify Parameter" if is_wr else "T0861: Point & Tag Identification",
                                f"CRITICAL: Attacker touched honeytoken register/tag '{tag or addr}' via {fname}! Reconnaissance trap sprung."
                            )

                    elif action == "alert":
                        raise_alert(cursor, *payload)

                    elif action == "end_session":
                        s_id, now, reason = payload
                        peers.pop(s_id, None)
                        cursor.execute("""
                            UPDATE sessions
                            SET is_active = 0,
                                last_seen = ?,
                                time_gained_seconds = MAX(0.0, ? - started_at),
                                notes = ?
                            WHERE session_id = ?
                        """, (now, now, reason, s_id))

                    elif action == "storyline":
                        now, title, narrative, adj_str = payload
                        cursor.execute("""
                            INSERT INTO storylines (timestamp, title, narrative, adjustments_json)
                            VALUES (?, ?, ?, ?)
                        """, (now, title, narrative, adj_str))

                conn.commit()
                # Only alerts that are safely recorded go to the SIEM.
                if self.alert_forwarder is not None:
                    for alert in outgoing:
                        try:
                            self.alert_forwarder.forward(alert)
                        except Exception as e:     # forwarding must never stop the writer thread
                            logger.error("Alert forwarding failed: %s", e)
            except Exception as e:
                logger.error("Error committing batched DB entries: %s", e, exc_info=True)
            finally:
                for _ in items:
                    self._queue.task_done()

        try:
            conn.close()
        except Exception:
            pass

    def start_session(self, client_ip: str, client_port: int, unit_id: int) -> str:
        """Record a new attacker connection (non-blocking)."""
        session_id = str(uuid.uuid4())
        now = time.time()
        if not self.read_only:
            self._queue.put(("start_session", (session_id, client_ip, client_port, unit_id, now)))
        return session_id

    def log_request(
        self,
        session_id: str,
        function_code: int,
        function_name: str,
        address: int,
        count: int,
        values: Any,
        latency_ms: float,
        response_status: str,
        tag_name: Optional[str] = None,
        is_honeytoken: bool = False,
        client_ip: Optional[str] = None,
    ):
        """Queue incoming request log (non-blocking, returns in < 0.1ms)."""
        if self.read_only:
            return

        now = time.time()
        is_write = function_code in (0x05, 0x06, 0x0F, 0x10)
        values_str = json.dumps(values) if values is not None else "[]"

        self._queue.put((
            "log_request",
            (session_id, now, function_code, function_name, address, count,
             values_str, latency_ms, response_status, tag_name, is_honeytoken, is_write)
        ))

        if client_ip:
            self._evaluate_visit_alerts(session_id, now, client_ip, address, tag_name, values_str,
                                        is_write, is_honeytoken)

    def _evaluate_visit_alerts(self, session_id: str, now: float, client_ip: str, address: int,
                               tag_name: Optional[str], values_str: str, is_write: bool, is_honeytoken: bool):
        """Scan and write alerts, re-armed for each visit (a new visit starts after VISIT_GAP_SECONDS of silence).

        Writes alert once per distinct tag per visit: repeated writes to one setpoint stay quiet,
        while an escalation to a new target (pump stop, breaker trip, shutdown) always raises a new alert.
        Honeytoken writes are left to the immediate HONEYTOKEN_TRIGGER alert.
        """
        visit = self._visits.get(client_ip)
        if visit is None or now - visit["last_seen"] > VISIT_GAP_SECONDS:
            self._forget_ended_visits(now)
            visit = {"requests": 0, "writes": 0, "scan_alerted": False, "tags_alerted": set()}
            self._visits[client_ip] = visit
        visit["last_seen"] = now
        visit["requests"] += 1

        if visit["requests"] >= self.alert_threshold_scans and not visit["scan_alerted"]:
            visit["scan_alerted"] = True
            self._queue.put((
                "alert",
                (session_id, now, "MEDIUM", "RECON_SCAN", "T0846: Remote System Discovery",
                 f"Attacker ({client_ip}) executed {visit['requests']} requests this visit. "
                 "Systematic OT reconnaissance underway.")
            ))

        if is_write:
            visit["writes"] += 1
            target = tag_name or f"address {address}"
            if (not is_honeytoken and visit["writes"] >= self.alert_threshold_writes
                    and target not in visit["tags_alerted"]):
                visit["tags_alerted"].add(target)
                self._queue.put((
                    "alert",
                    (session_id, now, "CRITICAL", "UNAUTHORIZED_WRITE", "T0855: Unauthorized Command Message",
                     f"Unauthorized write to '{target}' from {client_ip} with value {values_str} "
                     f"(write {visit['writes']} this visit).")
                ))

    def _forget_ended_visits(self, now: float) -> None:
        """Drop visits that have ended, so a decoy running for months doesn't keep an entry per address forever.

        Runs at most once a minute; an ended visit would be replaced by a fresh one on return anyway.
        """
        if now - self._visits_swept_at < 60.0:
            return
        self._visits_swept_at = now
        for ip in [ip for ip, v in self._visits.items() if now - v["last_seen"] > VISIT_GAP_SECONDS]:
            del self._visits[ip]

    def end_session(self, session_id: str, reason: str = "Client disconnected"):
        """Mark a session as completed (non-blocking)."""
        if not self.read_only:
            now = time.time()
            self._queue.put(("end_session", (session_id, now, reason)))

    def log_storyline(self, title: str, narrative: str, adjustments: Dict[str, Any]):
        """Record an operational narrative generated by the AI Director (non-blocking)."""
        if not self.read_only:
            now = time.time()
            self._queue.put(("storyline", (now, title, narrative, json.dumps(adjustments))))

    def flush(self):
        """Wait for all pending database writes to complete."""
        if not self.read_only:
            self._queue.join()

    def close(self):
        """Flush and stop background writer."""
        if not self.read_only:
            self._running = False
            self.flush()
            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=2.0)
            if self.alert_forwarder is not None:
                self.alert_forwarder.close()

    # --------------------------------------------------------------------------
    # SOC Metrics & Dashboard Queries
    # --------------------------------------------------------------------------

    def get_soc_metrics(self) -> Dict[str, Any]:
        """Compute aggregate SOC metrics including Time Gained clustered by visits."""
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()

            try:
                cursor.execute("SELECT COUNT(*) as count FROM sessions WHERE is_active = 1")
                active_count = cursor.fetchone()["count"]

                cursor.execute("SELECT COUNT(*) as count FROM sessions")
                total_sessions = cursor.fetchone()["count"]

                # Visit-based Time Gained: split an IP's activity into separate visits
                # if there is a gap > 1800s (30 minutes) between sessions/requests
                cursor.execute("""
                    SELECT client_ip, started_at, last_seen
                    FROM sessions
                    ORDER BY client_ip, started_at ASC
                """)
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                return {
                    "active_sessions": 0, "total_sessions": 0, "total_time_gained_seconds": 0.0,
                    "total_requests": 0, "total_writes": 0, "severity_counts": {}, "mitre_counts": {}
                }

            total_time_gained = 0.0

            current_ip = None
            visit_start = 0.0
            visit_end = 0.0

            for r in rows:
                ip = r["client_ip"]
                s_at = r["started_at"]
                l_seen = r["last_seen"]

                if ip != current_ip:
                    if current_ip is not None:
                        total_time_gained += max(0.0, visit_end - visit_start)
                    current_ip = ip
                    visit_start = s_at
                    visit_end = l_seen
                else:
                    if (s_at - visit_end) > VISIT_GAP_SECONDS:
                        total_time_gained += max(0.0, visit_end - visit_start)
                        visit_start = s_at
                        visit_end = l_seen
                    else:
                        visit_end = max(visit_end, l_seen)

            if current_ip is not None:
                total_time_gained += max(0.0, visit_end - visit_start)

            cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            severity_counts = {r["severity"]: r["count"] for r in cursor.fetchall()}

            cursor.execute("SELECT mitre_technique, COUNT(*) as count FROM alerts GROUP BY mitre_technique")
            mitre_counts = {r["mitre_technique"]: r["count"] for r in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) as count FROM requests")
            total_requests = cursor.fetchone()["count"]

            cursor.execute("SELECT SUM(total_writes) as count FROM sessions")
            total_writes = cursor.fetchone()["count"] or 0

            return {
                "active_sessions": active_count,
                "total_sessions": total_sessions,
                "total_time_gained_seconds": round(total_time_gained, 1),
                "total_requests": total_requests,
                "total_writes": total_writes,
                "severity_counts": severity_counts,
                "mitre_counts": mitre_counts,
            }

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT a.*, s.client_ip, s.client_port
                    FROM alerts a
                    JOIN sessions s ON a.session_id = s.session_id
                    ORDER BY a.timestamp DESC
                    LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        self.flush()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT *, (? - started_at) as live_duration_seconds
                    FROM sessions
                    WHERE is_active = 1
                    ORDER BY last_seen DESC
                """, (now,))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_all_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Newest sessions first, with their duration and how many requests touched a honeytoken."""
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT s.*,
                           MAX(0.0, s.last_seen - s.started_at) AS duration_seconds,
                           (SELECT COUNT(*) FROM requests r
                             WHERE r.session_id = s.session_id AND r.is_honeytoken = 1) AS honeytoken_hits
                    FROM sessions s
                    ORDER BY s.started_at DESC
                    LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_recent_requests(self, limit: int = 100, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                if session_id:
                    cursor.execute("""
                        SELECT r.*, s.client_ip
                        FROM requests r
                        JOIN sessions s ON r.session_id = s.session_id
                        WHERE r.session_id = ?
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (session_id, limit))
                else:
                    cursor.execute("""
                        SELECT r.*, s.client_ip
                        FROM requests r
                        JOIN sessions s ON r.session_id = s.session_id
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.OperationalError:
                return []

    def get_latest_storyline(self) -> Optional[Dict[str, Any]]:
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM storylines ORDER BY timestamp DESC LIMIT 1")
                row = cursor.fetchone()
                return dict(row) if row else None
            except sqlite3.OperationalError:
                return None
