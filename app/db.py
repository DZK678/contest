import os
import secrets
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  event_at TEXT NOT NULL,
  max_spots INTEGER NOT NULL CHECK(max_spots BETWEEN 1 AND 10000),
  cover_url TEXT,
  is_private INTEGER NOT NULL DEFAULT 0,
  invite_token TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(event_at);
CREATE TABLE IF NOT EXISTS bookings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(event_id, user_id));
CREATE TABLE IF NOT EXISTS comments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
"""


def db_path():
    return os.environ.get("DB_PATH", "tusovka.db")


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def conn():
    c = sqlite3.connect(db_path(), timeout=15, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=15000")
    return c


def init_db():
    c = conn()
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
    finally:
        c.close()


def q(sql, args=(), one=False):
    c = conn()
    try:
        rows = c.execute(sql, args).fetchall()
    finally:
        c.close()
    return (rows[0] if rows else None) if one else rows


def ex(sql, args=()):
    c = conn()
    try:
        cur = c.execute(sql, args)
        return cur.lastrowid
    finally:
        c.close()


def create_user(email, pw_hash):
    try:
        return ex("INSERT INTO users(email,password_hash) VALUES(?,?)", (email, pw_hash))
    except sqlite3.IntegrityError:
        return None


def create_event(author_id, title, description, event_at, max_spots, cover_url, is_private):
    return ex(
        "INSERT INTO events(author_id,title,description,event_at,max_spots,cover_url,is_private,invite_token)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (author_id, title, description, event_at, max_spots, cover_url, int(is_private),
         secrets.token_urlsafe(24)))


def update_event(event_id, author_id, title, description, event_at, max_spots, cover_url, is_private):
    """Атомарно: 'ok' | 'notfound' | 'forbidden' | 'too_few'."""
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        ev = c.execute("SELECT author_id FROM events WHERE id=?", (event_id,)).fetchone()
        if not ev:
            c.execute("ROLLBACK")
            return "notfound"
        if ev["author_id"] != author_id:
            c.execute("ROLLBACK")
            return "forbidden"
        cnt = c.execute("SELECT COUNT(*) FROM bookings WHERE event_id=?", (event_id,)).fetchone()[0]
        if max_spots < cnt:
            c.execute("ROLLBACK")
            return "too_few"
        c.execute(
            "UPDATE events SET title=?,description=?,event_at=?,max_spots=?,cover_url=?,is_private=?"
            " WHERE id=? AND author_id=?",
            (title, description, event_at, max_spots, cover_url, int(is_private), event_id, author_id))
        c.execute("COMMIT")
        return "ok"
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        c.close()


def delete_event(event_id, author_id):
    c = conn()
    try:
        return c.execute("DELETE FROM events WHERE id=? AND author_id=?", (event_id, author_id)).rowcount > 0
    finally:
        c.close()


def book(event_id, user_id):
    """Атомарний запис: 'ok' | 'notfound' | 'past' | 'dup' | 'full'."""
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        ev = c.execute("SELECT max_spots,event_at FROM events WHERE id=?", (event_id,)).fetchone()
        res = "ok"
        if not ev:
            res = "notfound"
        elif ev["event_at"] <= now_iso():
            res = "past"
        elif c.execute("SELECT 1 FROM bookings WHERE event_id=? AND user_id=?", (event_id, user_id)).fetchone():
            res = "dup"
        elif c.execute("SELECT COUNT(*) FROM bookings WHERE event_id=?", (event_id,)).fetchone()[0] >= ev["max_spots"]:
            res = "full"
        else:
            c.execute("INSERT INTO bookings(event_id,user_id) VALUES(?,?)", (event_id, user_id))
        c.execute("COMMIT" if res == "ok" else "ROLLBACK")
        return res
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        c.close()
