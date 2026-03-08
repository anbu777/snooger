"""
Checkpoint / Resume System — poin 14 dari perbaikan.
Menyimpan state tiap fase ke SQLite sehingga bisa di-resume jika crash.
"""
import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger('snooger')

PHASES = [
    'recon',
    'subdomain_enum',
    'alive_filter',
    'tech_detect',
    'content_discovery',
    'js_analysis',
    'port_scan',
    'ssl_tls',
    'vuln_scan',
    'vuln_validate',
    'idor',
    'api_testing',
    'auth_testing',
    'business_logic',
    'exploitation',
    'post_exploitation',
    'report',
]


class CheckpointManager:
    """
    Manages scan state in a SQLite database.
    Supports save/load per phase and per-finding deduplication.
    """

    def __init__(self, workspace_dir: str):
        self.db_path = os.path.join(workspace_dir, 'snooger_state.db')
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self):
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS phases (
                phase       TEXT PRIMARY KEY,
                status      TEXT DEFAULT 'pending',
                started_at  TEXT,
                finished_at TEXT,
                data        TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_type   TEXT,
                url         TEXT,
                parameter   TEXT,
                severity    TEXT,
                confidence  REAL,
                data        TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key   TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
                ON findings(vuln_type, url, parameter);
        """)
        conn.commit()

    # ─── Phase Management ─────────────────────────────────────────────────────

    def phase_status(self, phase: str) -> str:
        """Return status of a phase: 'pending', 'running', 'done', 'failed'."""
        conn = self._connect()
        row = conn.execute("SELECT status FROM phases WHERE phase=?", (phase,)).fetchone()
        return row['status'] if row else 'pending'

    def phase_done(self, phase: str) -> bool:
        return self.phase_status(phase) == 'done'

    def start_phase(self, phase: str):
        conn = self._connect()
        conn.execute("""
            INSERT INTO phases (phase, status, started_at)
            VALUES (?, 'running', ?)
            ON CONFLICT(phase) DO UPDATE SET status='running', started_at=?
        """, (phase, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
        conn.commit()
        logger.debug(f"[Checkpoint] Phase '{phase}' started")

    def finish_phase(self, phase: str, data: Any = None):
        conn = self._connect()
        conn.execute("""
            INSERT INTO phases (phase, status, finished_at, data)
            VALUES (?, 'done', ?, ?)
            ON CONFLICT(phase) DO UPDATE SET status='done', finished_at=?, data=?
        """, (phase, datetime.utcnow().isoformat(), json.dumps(data, default=str),
              datetime.utcnow().isoformat(), json.dumps(data, default=str)))
        conn.commit()
        logger.info(f"[Checkpoint] Phase '{phase}' completed")

    def fail_phase(self, phase: str, error: str = ''):
        conn = self._connect()
        conn.execute("""
            INSERT INTO phases (phase, status, data)
            VALUES (?, 'failed', ?)
            ON CONFLICT(phase) DO UPDATE SET status='failed', data=?
        """, (phase, error, error))
        conn.commit()
        logger.warning(f"[Checkpoint] Phase '{phase}' failed: {error}")

    def get_phase_data(self, phase: str) -> Any:
        conn = self._connect()
        row = conn.execute("SELECT data FROM phases WHERE phase=?", (phase,)).fetchone()
        if row and row['data']:
            try:
                return json.loads(row['data'])
            except json.JSONDecodeError:
                return row['data']
        return None

    def reset_phase(self, phase: str):
        conn = self._connect()
        conn.execute("DELETE FROM phases WHERE phase=?", (phase,))
        conn.commit()

    def reset_all(self):
        conn = self._connect()
        conn.execute("DELETE FROM phases")
        conn.execute("DELETE FROM findings")
        conn.commit()
        logger.info("[Checkpoint] All state reset")

    def pending_phases(self, skip_phases: list = None) -> list:
        """Return list of phases that haven't completed yet."""
        skip = set(skip_phases or [])
        return [p for p in PHASES if p not in skip and not self.phase_done(p)]

    # ─── Findings Storage ─────────────────────────────────────────────────────

    def save_finding(self, finding: dict) -> bool:
        """
        Save a finding to DB. Returns False if it's a duplicate.
        """
        vuln_type = finding.get('type', finding.get('info', {}).get('name', 'unknown'))
        url = finding.get('url', finding.get('host', finding.get('matched-at', '')))
        parameter = finding.get('parameter', '')
        severity = finding.get('severity', finding.get('info', {}).get('severity', 'unknown'))
        confidence = finding.get('confidence', 0.0)

        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO findings (vuln_type, url, parameter, severity, confidence, data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (vuln_type, url, parameter, severity, confidence, json.dumps(finding, default=str)))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Duplicate

    def load_all_findings(self, min_confidence: float = 0.0) -> list:
        conn = self._connect()
        rows = conn.execute(
            "SELECT data FROM findings WHERE confidence >= ? ORDER BY confidence DESC",
            (min_confidence,)
        ).fetchall()
        results = []
        for row in rows:
            try:
                results.append(json.loads(row['data']))
            except json.JSONDecodeError:
                continue
        return results

    def findings_count(self) -> int:
        conn = self._connect()
        return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    # ─── Metadata ────────────────────────────────────────────────────────────

    def set_meta(self, key: str, value: Any):
        conn = self._connect()
        conn.execute("""
            INSERT INTO metadata (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=?
        """, (key, json.dumps(value, default=str), json.dumps(value, default=str)))
        conn.commit()

    def get_meta(self, key: str, default=None) -> Any:
        conn = self._connect()
        row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row:
            try:
                return json.loads(row['value'])
            except json.JSONDecodeError:
                return row['value']
        return default

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
