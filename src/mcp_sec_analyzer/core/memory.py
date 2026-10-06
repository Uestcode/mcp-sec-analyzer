"""Universal persistent multi-skill investigation and context memory engine."""

from __future__ import annotations

import datetime
import functools
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable

# Default memory database location inside workspace root
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".mcp_memory"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "unified_memory.db"


class UniversalMemory:
    """Universal persistent memory engine tracking all skills, tool executions, and knowledge items."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            env_path = os.environ.get("MCP_MEMORY_DB_PATH")
            self.db_path = Path(env_path) if env_path else DEFAULT_DB_PATH
        else:
            self.db_path = Path(db_path)

        self._current_session_id: str | None = None
        self._ensure_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_db(self) -> None:
        """Initialize database folder and schema tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    active_skill TEXT,
                    target TEXT,
                    target_metadata TEXT,
                    last_active_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    skill TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT,
                    summary TEXT,
                    status TEXT NOT NULL,
                    duration_ms REAL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                );

                CREATE TABLE IF NOT EXISTS knowledge_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    skill TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT,
                    target_ref TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                );

                CREATE INDEX IF NOT EXISTS idx_activity_session ON activity_log(session_id);
                CREATE INDEX IF NOT EXISTS idx_activity_skill ON activity_log(skill);
                CREATE INDEX IF NOT EXISTS idx_knowledge_session ON knowledge_items(session_id);
                CREATE INDEX IF NOT EXISTS idx_knowledge_skill ON knowledge_items(skill);
                CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_items(category);
            """)

    def get_or_create_session(
        self,
        skill: str = "general",
        target: str | None = None,
        target_metadata: dict[str, Any] | None = None,
    ) -> str:
        """Get or create an active investigation session."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not self._current_session_id:
            target_slug = Path(target).stem if target else skill
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self._current_session_id = f"{target_slug}_{stamp}"

        meta_json = json.dumps(target_metadata or {}, ensure_ascii=False)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, started_at, active_skill, target, target_metadata, last_active_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    active_skill = COALESCE(?, active_skill),
                    target = COALESCE(?, target),
                    target_metadata = COALESCE(?, target_metadata),
                    last_active_at = ?
                """,
                (
                    self._current_session_id,
                    now,
                    skill,
                    target,
                    meta_json,
                    now,
                    skill,
                    target,
                    meta_json,
                    now,
                ),
            )
        return self._current_session_id

    def log_activity(
        self,
        skill: str,
        tool_name: str,
        arguments: dict[str, Any],
        summary: str,
        status: str = "success",
        duration_ms: float = 0.0,
    ) -> None:
        """Automatically log tool execution from any skill."""
        session_id = self.get_or_create_session(skill=skill)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        clean_args = {k: str(v)[:250] for k, v in arguments.items()}
        args_json = json.dumps(clean_args, ensure_ascii=False)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO activity_log (session_id, timestamp, skill, tool_name, arguments_json, summary, status, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, now, skill, tool_name, args_json, summary[:500], status, duration_ms),
            )
            conn.execute(
                "UPDATE sessions SET active_skill = ?, last_active_at = ? WHERE session_id = ?",
                (skill, now, session_id),
            )

    def remember(
        self,
        title: str,
        content: str,
        category: str = "finding",
        tags: list[str] | str | None = None,
        skill: str = "general",
        target_ref: str | None = None,
    ) -> dict[str, Any]:
        """Save a discrete knowledge item, observation, note, or hypothesis."""
        session_id = self.get_or_create_session(skill=skill)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if isinstance(tags, list):
            tags_str = ", ".join(tags)
        elif isinstance(tags, str):
            tags_str = tags
        else:
            tags_str = ""

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO knowledge_items (session_id, timestamp, skill, category, title, content, tags, target_ref)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, now, skill, category.lower(), title, content, tags_str, target_ref),
            )
            item_id = cursor.lastrowid

        return {
            "status": "stored",
            "id": item_id,
            "session_id": session_id,
            "timestamp": now,
            "skill": skill,
            "category": category,
            "title": title,
            "tags": tags_str,
            "target_ref": target_ref,
        }

    def recall(
        self,
        query: str | None = None,
        skill: str | None = None,
        tag: str | None = None,
        category: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search and recall past knowledge items across all skills and sessions."""
        sql = "SELECT * FROM knowledge_items WHERE 1=1"
        params: list[Any] = []

        if skill:
            sql += " AND skill = ?"
            params.append(skill.lower())

        if query:
            sql += " AND (title LIKE ? OR content LIKE ?)"
            pattern = f"%{query}%"
            params.extend([pattern, pattern])

        if tag:
            sql += " AND tags LIKE ?"
            params.append(f"%{tag}%")

        if category:
            sql += " AND category = ?"
            params.append(category.lower())

        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [dict(row) for row in rows]

    def get_timeline(
        self,
        skill: str | None = None,
        limit: int = 50,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve chronological history of tool actions across any or all skills."""
        sql = "SELECT id, timestamp, skill, tool_name, summary, status, duration_ms FROM activity_log WHERE 1=1"
        params: list[Any] = []

        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)

        if skill:
            sql += " AND skill = ?"
            params.append(skill.lower())

        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [dict(row) for row in rows]

    def export_report(self, skill: str | None = None, session_id: str | None = None) -> str:
        """Generate a complete Markdown investigation report across all skills."""
        target_session = session_id or self._current_session_id
        if not target_session:
            return "# Relatório de Investigação\n_Nenhuma sessão ativa encontrada._"

        with self._get_connection() as conn:
            session_row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (target_session,),
            ).fetchone()

            k_sql = "SELECT * FROM knowledge_items WHERE session_id = ?"
            k_params: list[Any] = [target_session]
            if skill:
                k_sql += " AND skill = ?"
                k_params.append(skill.lower())
            k_sql += " ORDER BY id ASC"
            findings = conn.execute(k_sql, k_params).fetchall()

            a_sql = "SELECT * FROM activity_log WHERE session_id = ?"
            a_params: list[Any] = [target_session]
            if skill:
                a_sql += " AND skill = ?"
                a_params.append(skill.lower())
            a_sql += " ORDER BY id ASC"
            activities = conn.execute(a_sql, a_params).fetchall()

        s_dict = dict(session_row) if session_row else {}

        md = []
        md.append(f"# [INVESTIGATION REPORT] `{s_dict.get('target') or target_session}`")
        md.append(f"**Session ID:** `{target_session}`  ")
        md.append(f"**Primary Skill:** `{s_dict.get('active_skill', 'multi-skill')}`  ")
        md.append(f"**Started At:** {s_dict.get('started_at')}  ")
        md.append(f"**Last Activity:** {s_dict.get('last_active_at')}  ")
        md.append("")

        md.append("## Findings & Knowledge Base")
        if not findings:
            md.append("_No findings explicitly registered for this session._\n")
        else:
            for item in findings:
                i_dict = dict(item)
                skill_badge = f"`[{i_dict['skill'].upper()}]`"
                cat_badge = f"**[{i_dict['category'].upper()}]**"
                target_str = f" (`{i_dict['target_ref']}`)" if i_dict.get("target_ref") else ""
                md.append(f"### {skill_badge} {cat_badge} {i_dict['title']}{target_str}")
                md.append(f"*{i_dict['timestamp']}* | Tags: `{i_dict.get('tags') or 'general'}`\n")
                md.append(f"{i_dict['content']}\n")

        md.append("## Activity Timeline")
        if not activities:
            md.append("_Nenhuma atividade registrada._\n")
        else:
            md.append("| Horário | Skill | Ferramenta | Status | Resumo |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for act in activities:
                a_dict = dict(act)
                md.append(
                    f"| {a_dict['timestamp'][11:19]} | `{a_dict['skill']}` | `{a_dict['tool_name']}` | {a_dict['status']} | {a_dict['summary']} |"
                )
            md.append("")

        return "\n".join(md)

    def clear(self, confirm: bool = False, skill: str | None = None) -> dict[str, str]:
        """Clear memory records with safety confirmation."""
        if not confirm:
            return {"status": "cancelled", "message": "Specify confirm=True to purge memory."}

        with self._get_connection() as conn:
            if skill:
                conn.execute("DELETE FROM knowledge_items WHERE skill = ?", (skill.lower(),))
                conn.execute("DELETE FROM activity_log WHERE skill = ?", (skill.lower(),))
                msg = f"Cleared memory for skill '{skill}'"
            else:
                conn.execute("DELETE FROM knowledge_items")
                conn.execute("DELETE FROM activity_log")
                conn.execute("DELETE FROM sessions")
                self._current_session_id = None
                msg = "Cleared entire unified memory database"

        return {"status": "ok", "message": msg}


# Global memory singleton instance
unified_memory = UniversalMemory()
