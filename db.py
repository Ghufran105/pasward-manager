"""SQLite database layer. Only encrypted blobs are stored for vault data.

Swap this file for a Supabase/Postgres version later without touching app.py,
as long as the same function names are kept.
"""
import os
import sqlite3
import time
from contextlib import contextmanager

MAX_ATTEMPTS = 5
LOCK_SECONDS = 30


def _path() -> str:
    return os.environ.get("VAULT_DB_PATH", "vault.db")


@contextmanager
def _conn():
    con = sqlite3.connect(_path())
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        con.execute(
            """CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                verifier TEXT NOT NULL,
                created_at REAL NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )"""
        )
        con.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                blob TEXT NOT NULL,
                updated_at REAL NOT NULL
            )"""
        )


def create_user(username: str, salt: str, verifier: str) -> bool:
    try:
        with _conn() as con:
            con.execute(
                "INSERT INTO users (username, salt, verifier, created_at) VALUES (?,?,?,?)",
                (username, salt, verifier, time.time()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(username: str):
    with _conn() as con:
        row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None


def lock_remaining(username: str) -> int:
    user = get_user(username)
    if not user:
        return 0
    return max(0, int(user["locked_until"] - time.time() + 0.999))


def record_failed_attempt(username: str) -> int:
    """Returns remaining lock seconds (0 if not locked)."""
    with _conn() as con:
        row = con.execute(
            "SELECT failed_attempts FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return 0
        attempts = row["failed_attempts"] + 1
        locked_until = 0.0
        if attempts >= MAX_ATTEMPTS:
            locked_until = time.time() + LOCK_SECONDS
            attempts = 0
        con.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            (attempts, locked_until, username),
        )
    return lock_remaining(username)


def reset_attempts(username: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
            (username,),
        )


def add_entry(username: str, blob: str) -> int:
    with _conn() as con:
        cur = con.execute(
            "INSERT INTO entries (username, blob, updated_at) VALUES (?,?,?)",
            (username, blob, time.time()),
        )
        return cur.lastrowid


def list_entries(username: str) -> list:
    with _conn() as con:
        rows = con.execute(
            "SELECT id, blob, updated_at FROM entries WHERE username=? ORDER BY id",
            (username,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_entry(entry_id: int, username: str, blob: str) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE entries SET blob=?, updated_at=? WHERE id=? AND username=?",
            (blob, time.time(), entry_id, username),
        )


def delete_entry(entry_id: int, username: str) -> None:
    with _conn() as con:
        con.execute(
            "DELETE FROM entries WHERE id=? AND username=?", (entry_id, username)
        )
