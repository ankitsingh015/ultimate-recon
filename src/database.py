import json
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

class ReconDatabase:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.output_dir / "recon.db"
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS target (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'pending'
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                subdomain TEXT NOT NULL,
                source TEXT,
                ip TEXT,
                resolved INTEGER DEFAULT 0,
                first_seen TEXT,
                category TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                ip TEXT NOT NULL,
                asn TEXT,
                cidr TEXT,
                source TEXT,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                url TEXT NOT NULL,
                source TEXT,
                status_code INTEGER,
                content_type TEXT,
                tech_stack TEXT,
                has_params INTEGER DEFAULT 0,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                description TEXT,
                verified INTEGER DEFAULT 0,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS js_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                url TEXT NOT NULL,
                endpoints_found INTEGER DEFAULT 0,
                secrets_found INTEGER DEFAULT 0,
                content_hash TEXT,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                banner TEXT,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS tech_stack (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                url TEXT,
                technology TEXT,
                category TEXT,
                version TEXT,
                first_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES target(id)
            );

            CREATE TABLE IF NOT EXISTS checkpoint (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase TEXT NOT NULL,
                status TEXT,
                data JSON,
                updated_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_id);
            CREATE INDEX IF NOT EXISTS idx_urls_target ON urls(target_id);
            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type, severity);
        """)

    def save_raw(self, category: str, data: Any, filename: str):
        raw_dir = self.output_dir / "all_results"
        raw_dir.mkdir(exist_ok=True)
        filepath = raw_dir / filename

        if isinstance(data, (list, set)):
            data = "\n".join(sorted(data))

        if isinstance(data, str):
            with open(filepath, "w") as f:
                f.write(data)
        elif isinstance(data, (dict, list)):
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

        mega = raw_dir / "all-everything.txt"
        if isinstance(data, str):
            with open(mega, "a") as f:
                f.write(f"\n### {filename} ({category})\n")
                f.write(data)
                f.write("\n")

        return str(filepath)

    def append_raw(self, category: str, data: str, filename: str):
        raw_dir = self.output_dir / "all_results"
        raw_dir.mkdir(exist_ok=True)
        filepath = raw_dir / filename
        with open(filepath, "a") as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")

        mega = raw_dir / "all-everything.txt"
        with open(mega, "a") as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")

    def save_checkpoint(self, phase: str, status: str, data: dict = None):
        now = datetime.utcnow().isoformat()
        data_json = json.dumps(data) if data else "{}"
        self.conn.execute(
            """INSERT OR REPLACE INTO checkpoint (id, phase, status, data, updated_at)
               VALUES ((SELECT id FROM checkpoint WHERE phase=? LIMIT 1), ?, ?, ?, ?)""",
            (phase, phase, status, data_json, now)
        )
        self.conn.commit()

    def get_checkpoint(self) -> Optional[dict]:
        cursor = self.conn.execute(
            "SELECT phase, status, data, updated_at FROM checkpoint ORDER BY updated_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            return {
                "phase": row[0],
                "status": row[1],
                "data": json.loads(row[2]) if row[2] else {},
                "updated_at": row[3]
            }
        return None

    def add_finding(self, target_id: int, ftype: str, severity: str, url: str = None,
                    parameter: str = None, payload: str = None, evidence: str = None,
                    description: str = None, verified: bool = False):
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            """INSERT INTO findings (target_id, type, severity, url, parameter, payload,
               evidence, description, verified, first_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (target_id, ftype, severity, url, parameter, payload,
             evidence, description, int(verified), now)
        )
        self.conn.commit()

    def add_subdomains(self, target_id: int, subdomains: list, source: str = ""):
        now = datetime.utcnow().isoformat()
        rows = [(target_id, s.strip(), source, "", 0, now, "") for s in subdomains if s.strip()]
        self.conn.executemany(
            "INSERT OR IGNORE INTO subdomains (target_id, subdomain, source, ip, resolved, first_seen, category) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows
        )
        self.conn.commit()

    def get_all_subdomains(self, target_id: int) -> list:
        cursor = self.conn.execute(
            "SELECT subdomain FROM subdomains WHERE target_id=?", (target_id,)
        )
        return [row[0] for row in cursor.fetchall()]

    def get_all_findings(self, target_id: int, severity: str = None) -> list:
        if severity:
            cursor = self.conn.execute(
                "SELECT * FROM findings WHERE target_id=? AND severity=? ORDER BY severity DESC",
                (target_id, severity)
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM findings WHERE target_id=? ORDER BY severity DESC",
                (target_id,)
            )
        return cursor.fetchall()

    def get_stats(self, target_id: int) -> dict:
        return {
            "subdomains": self.conn.execute("SELECT COUNT(*) FROM subdomains WHERE target_id=?", (target_id,)).fetchone()[0],
            "urls": self.conn.execute("SELECT COUNT(*) FROM urls WHERE target_id=?", (target_id,)).fetchone()[0],
            "findings": self.conn.execute("SELECT COUNT(*) FROM findings WHERE target_id=?", (target_id,)).fetchone()[0],
            "ips": self.conn.execute("SELECT COUNT(*) FROM ips WHERE target_id=?", (target_id,)).fetchone()[0],
            "ports": self.conn.execute("SELECT COUNT(*) FROM ports WHERE target_id=?", (target_id,)).fetchone()[0],
            "critical": self.conn.execute("SELECT COUNT(*) FROM findings WHERE target_id=? AND severity='critical'", (target_id,)).fetchone()[0],
            "high": self.conn.execute("SELECT COUNT(*) FROM findings WHERE target_id=? AND severity='high'", (target_id,)).fetchone()[0],
            "medium": self.conn.execute("SELECT COUNT(*) FROM findings WHERE target_id=? AND severity='medium'", (target_id,)).fetchone()[0],
            "low": self.conn.execute("SELECT COUNT(*) FROM findings WHERE target_id=? AND severity='low'", (target_id,)).fetchone()[0],
        }

    def log_session_event(self, workspace_dir: str, event: dict):
        log_path = Path(workspace_dir) / "session.jsonl"
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(log_path, "a") as f:
            f.write(json.dumps(event) + "\n")

    def log_chat(self, workspace_dir: str, role: str, message: str, metadata: dict = None):
        chat_path = Path(workspace_dir) / "chat.jsonl"
        entry = {
            "role": role,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if metadata:
            entry["metadata"] = metadata
        with open(chat_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_session_log(self, workspace_dir: str, limit: int = 100) -> list:
        log_path = Path(workspace_dir) / "session.jsonl"
        if not log_path.exists():
            return []
        events = []
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events[-limit:]

    def get_chat_log(self, workspace_dir: str, limit: int = 100) -> list:
        chat_path = Path(workspace_dir) / "chat.jsonl"
        if not chat_path.exists():
            return []
        messages = []
        with open(chat_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        messages.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return messages[-limit:]

    def save_ai_decision(self, workspace_dir: str, phase: int, prompt: str, response: dict):
        decision_dir = Path(workspace_dir) / "ai_decisions"
        decision_dir.mkdir(parents=True, exist_ok=True)
        with open(decision_dir / f"phase{phase}-prompt.txt", "w") as f:
            f.write(prompt)
        with open(decision_dir / f"phase{phase}-response.json", "w") as f:
            json.dump(response, f, indent=2)

    def close(self):
        self.conn.close()
