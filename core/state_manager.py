"""
SQLite-based state manager for scan persistence, resume capability,
historical comparison, and cross-module data sharing.
"""
import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import Optional, List, Any

logger = logging.getLogger('snooger')

class StateManager:
    def __init__(self, workspace_dir: str, target: str):
        self.workspace_dir = workspace_dir
        self.target = target
        self.db_path = os.path.join(workspace_dir, 'snooger_state.db')
        self._conn = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_meta (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                status TEXT DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS phase_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                phase TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                result_summary TEXT,
                FOREIGN KEY(scan_id) REFERENCES scan_meta(id)
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                phase TEXT,
                type TEXT,
                severity TEXT,
                url TEXT,
                name TEXT,
                data TEXT,
                ai_priority INTEGER DEFAULT 0,
                ai_confidence INTEGER DEFAULT 50,
                validated INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY(scan_id) REFERENCES scan_meta(id)
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                domain TEXT,
                alive INTEGER DEFAULT 0,
                in_scope INTEGER DEFAULT 1,
                technologies TEXT,
                FOREIGN KEY(scan_id) REFERENCES scan_meta(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
        """)
        conn.commit()

    def create_scan(self) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO scan_meta (target, start_time, status) VALUES (?, ?, 'running')",
            (self.target, datetime.utcnow().isoformat())
        )
        conn.commit()
        self.scan_id = cur.lastrowid
        return self.scan_id

    def get_or_create_scan(self) -> int:
        """Resume existing incomplete scan or create new one."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT id FROM scan_meta WHERE target=? AND status='running' ORDER BY id DESC LIMIT 1",
            (self.target,)
        ).fetchone()
        if row:
            self.scan_id = row['id']
            logger.info(f"Resuming scan ID {self.scan_id} for {self.target}")
            return self.scan_id
        return self.create_scan()

    def complete_scan(self) -> None:
        conn = self._get_conn()
        conn.execute(
            "UPDATE scan_meta SET end_time=?, status='completed' WHERE id=?",
            (datetime.utcnow().isoformat(), self.scan_id)
        )
        conn.commit()

    def checkpoint_phase(self, phase: str, status: str = 'completed',
                         summary: Any = None) -> None:
        conn = self._get_conn()
        existing = conn.execute(
            "SELECT id FROM phase_checkpoints WHERE scan_id=? AND phase=?",
            (self.scan_id, phase)
        ).fetchone()
        now = datetime.utcnow().isoformat()
        summary_str = json.dumps(summary) if summary is not None else None
        if existing:
            conn.execute(
                "UPDATE phase_checkpoints SET status=?, completed_at=?, result_summary=? WHERE id=?",
                (status, now, summary_str, existing['id'])
            )
        else:
            conn.execute(
                "INSERT INTO phase_checkpoints (scan_id, phase, status, started_at, completed_at, result_summary) VALUES (?,?,?,?,?,?)",
                (self.scan_id, phase, status, now, now, summary_str)
            )
        conn.commit()

    def is_phase_completed(self, phase: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT status FROM phase_checkpoints WHERE scan_id=? AND phase=?",
            (self.scan_id, phase)
        ).fetchone()
        return row is not None and row['status'] == 'completed'

    def save_finding(self, phase: str, finding_type: str, severity: str,
                     url: str, name: str, data: dict) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO findings
               (scan_id, phase, type, severity, url, name, data, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (self.scan_id, phase, finding_type, severity, url, name,
             json.dumps(data), datetime.utcnow().isoformat())
        )
        conn.commit()
        return cur.lastrowid

    def get_findings(self, severity: Optional[str] = None,
                     finding_type: Optional[str] = None,
                     validated_only: bool = False) -> List[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM findings WHERE scan_id=?"
        params = [self.scan_id]
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if finding_type:
            query += " AND type=?"
            params.append(finding_type)
        if validated_only:
            query += " AND validated=1"
        rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d['data'] = json.loads(d['data'])
            except Exception:
                pass
            results.append(d)
        return results

    def save_subdomains(self, subdomains: List[dict]) -> None:
        conn = self._get_conn()
        for sub in subdomains:
            conn.execute(
                "INSERT OR IGNORE INTO subdomains (scan_id, domain, alive, in_scope, technologies) VALUES (?,?,?,?,?)",
                (self.scan_id, sub.get('domain', ''), int(sub.get('alive', 0)),
                 int(sub.get('in_scope', 1)), json.dumps(sub.get('technologies', [])))
            )
        conn.commit()

    def get_new_findings_vs_last_scan(self) -> List[dict]:
        """Return findings not present in previous scan (delta reporting)."""
        conn = self._get_conn()
        prev = conn.execute(
            "SELECT id FROM scan_meta WHERE target=? AND status='completed' ORDER BY id DESC LIMIT 1",
            (self.target,)
        ).fetchone()
        if not prev:
            return self.get_findings()
        prev_urls = set(
            row['url'] for row in conn.execute(
                "SELECT url FROM findings WHERE scan_id=?", (prev['id'],)
            ).fetchall()
        )
        current = self.get_findings()
        return [f for f in current if f.get('url') not in prev_urls]

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
