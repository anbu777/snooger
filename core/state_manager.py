"""
State Manager v3.0 — unified state persistence with SQLite.
Merged checkpoint.py functionality. Supports scan resume, delta reports, and phase tracking.
"""
import os
import json
import sqlite3
import hashlib
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

logger = logging.getLogger('snooger')


class StateManager:
    """Unified state management with SQLite backend."""

    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        os.makedirs(workspace_dir, exist_ok=True)
        self.db_path = os.path.join(workspace_dir, 'state.db')
        self.conn = sqlite3.connect(self.db_path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        c = self.conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS phases (
                name TEXT PRIMARY KEY,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                data TEXT DEFAULT '{}',
                error TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE,
                type TEXT,
                severity TEXT,
                url TEXT,
                evidence TEXT,
                source TEXT,
                data TEXT DEFAULT '{}',
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_new INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
        """)
        self.conn.commit()

    # ─── Phase Management ─────────────────────────────────────────────

    def start_phase(self, phase_name: str) -> None:
        """Mark a phase as running."""
        c = self.conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO phases (name, status, started_at)
            VALUES (?, 'running', ?)
        """, (phase_name, datetime.utcnow().isoformat()))
        self.conn.commit()

    def complete_phase(self, phase_name: str) -> None:
        """Mark a phase as completed."""
        c = self.conn.cursor()
        c.execute("""
            UPDATE phases SET status='done', completed_at=? WHERE name=?
        """, (datetime.utcnow().isoformat(), phase_name))
        self.conn.commit()

    def fail_phase(self, phase_name: str, error: str = '') -> None:
        """Mark a phase as failed."""
        c = self.conn.cursor()
        c.execute("""
            UPDATE phases SET status='failed', error=?, completed_at=? WHERE name=?
        """, (error, datetime.utcnow().isoformat(), phase_name))
        self.conn.commit()

    def get_phase_status(self, phase_name: str) -> Optional[str]:
        """Get the status of a phase."""
        c = self.conn.cursor()
        c.execute("SELECT status FROM phases WHERE name=?", (phase_name,))
        row = c.fetchone()
        return row['status'] if row else None

    def is_phase_done(self, phase_name: str) -> bool:
        return self.get_phase_status(phase_name) == 'done'

    def save_phase_data(self, phase_name: str, data: Any) -> None:
        """Save phase results data."""
        c = self.conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO phases (name, status, data)
            VALUES (?, COALESCE((SELECT status FROM phases WHERE name=?), 'done'), ?)
        """, (phase_name, phase_name, json.dumps(data, default=str)))
        self.conn.commit()

    def get_phase_data(self, phase_name: str) -> Any:
        """Retrieve phase results data."""
        c = self.conn.cursor()
        c.execute("SELECT data FROM phases WHERE name=?", (phase_name,))
        row = c.fetchone()
        if row and row['data']:
            try:
                return json.loads(row['data'])
            except json.JSONDecodeError:
                return {}
        return {}

    def get_all_phases(self) -> List[dict]:
        """Get status of all phases."""
        c = self.conn.cursor()
        c.execute("SELECT name, status, started_at, completed_at FROM phases ORDER BY rowid")
        return [dict(row) for row in c.fetchall()]

    # ─── Findings Management ──────────────────────────────────────────

    def _hash_finding(self, finding: dict) -> str:
        key = '|'.join([
            str(finding.get('type', '')),
            str(finding.get('url', finding.get('matched-at', ''))),
            str(finding.get('severity', '')),
        ])
        return hashlib.md5(key.encode()).hexdigest()

    def add_finding(self, finding: dict, source: str = '') -> bool:
        """Add a finding with deduplication. Returns True if new."""
        h = self._hash_finding(finding)
        c = self.conn.cursor()
        try:
            c.execute("""
                INSERT INTO findings (hash, type, severity, url, evidence, source, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                h,
                finding.get('type', 'unknown'),
                finding.get('severity', 'info'),
                finding.get('url', finding.get('matched-at', '')),
                str(finding.get('evidence', ''))[:2000],
                source,
                json.dumps(finding, default=str),
            ))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_findings(self, findings: List[dict], source: str = '') -> int:
        """Add multiple findings. Returns count of new findings."""
        new_count = 0
        for f in findings:
            if self.add_finding(f, source):
                new_count += 1
        return new_count

    def get_findings(self, severity: Optional[str] = None,
                     vuln_type: Optional[str] = None,
                     limit: int = 1000) -> List[dict]:
        """Get findings with optional filters."""
        c = self.conn.cursor()
        query = "SELECT data FROM findings WHERE 1=1"
        params = []

        if severity:
            query += " AND severity=?"
            params.append(severity)
        if vuln_type:
            query += " AND type=?"
            params.append(vuln_type)

        query += f" ORDER BY CASE severity "
        query += "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        query += "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        query += f" LIMIT ?"
        params.append(limit)

        c.execute(query, params)
        results = []
        for row in c.fetchall():
            try:
                results.append(json.loads(row['data']))
            except json.JSONDecodeError:
                pass
        return results

    def findings_count(self) -> int:
        """Get total findings count."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) as cnt FROM findings")
        return c.fetchone()['cnt']

    def findings_by_severity(self) -> Dict[str, int]:
        """Get findings count grouped by severity."""
        c = self.conn.cursor()
        c.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity")
        return {row['severity']: row['cnt'] for row in c.fetchall()}

    def get_new_findings(self) -> List[dict]:
        """Get findings marked as new (for delta reporting)."""
        c = self.conn.cursor()
        c.execute("SELECT data FROM findings WHERE is_new=1")
        results = []
        for row in c.fetchall():
            try:
                results.append(json.loads(row['data']))
            except json.JSONDecodeError:
                pass
        return results

    def mark_all_as_old(self) -> None:
        """Mark all findings as old (after generating delta report)."""
        c = self.conn.cursor()
        c.execute("UPDATE findings SET is_new=0")
        self.conn.commit()

    # ─── Metadata ─────────────────────────────────────────────────────

    def set_metadata(self, key: str, value: str) -> None:
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                  (key, value))
        self.conn.commit()

    def get_metadata(self, key: str, default: str = '') -> str:
        c = self.conn.cursor()
        c.execute("SELECT value FROM metadata WHERE key=?", (key,))
        row = c.fetchone()
        return row['value'] if row else default

    # ─── Cleanup ──────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset all state data."""
        c = self.conn.cursor()
        c.executescript("""
            DELETE FROM phases;
            DELETE FROM findings;
            DELETE FROM metadata;
        """)
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
