import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
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


# Глобальне серіалізування записів у межах процесу: жодних "database is locked" під навантаженням
WRITE_LOCK = threading.Lock()


@contextmanager
def write_conn():
    with WRITE_LOCK:
        c = conn()
        try:
            yield c
        finally:
            c.close()


def conn():
    path = db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    c = sqlite3.connect(path, timeout=15, isolation_level=None, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout = 15000")
    c.execute("PRAGMA foreign_keys = ON")
    return c


def _schema(c):
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            c.execute(stmt)


def _migrate_cascade(c):
    """Старі БД без ON DELETE CASCADE: перебудовуємо таблиці зі збереженням даних."""
    tables = [t for t in ("events", "bookings", "comments")
              if any(fk["on_delete"].upper() != "CASCADE"
                     for fk in c.execute(f"PRAGMA foreign_key_list({t})").fetchall())]
    if not tables:
        return
    c.execute("PRAGMA foreign_keys = OFF")
    c.execute("PRAGMA legacy_alter_table = ON")  # не переписувати посилання FK в інших таблицях
    try:
        c.execute("BEGIN IMMEDIATE")
        for t in tables:
            c.execute(f"ALTER TABLE {t} RENAME TO _old_{t}")
        _schema(c)
        for t in tables:
            new = {r["name"] for r in c.execute(f"PRAGMA table_info({t})")}
            cols = ",".join(r["name"] for r in c.execute(f"PRAGMA table_info(_old_{t})") if r["name"] in new)
            c.execute(f"INSERT INTO {t}({cols}) SELECT {cols} FROM _old_{t}")
        for t in tables:
            c.execute(f"DROP TABLE _old_{t}")
        _schema(c)  # відновити індекси
        c.execute("COMMIT")
    finally:
        if c.in_transaction:
            c.execute("ROLLBACK")
        c.execute("PRAGMA legacy_alter_table = OFF")
        c.execute("PRAGMA foreign_keys = ON")


def init_db():
    with write_conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        _schema(c)
        _migrate_cascade(c)


def q(sql, args=(), one=False):
    c = conn()
    try:
        rows = c.execute(sql, args).fetchall()
    finally:
        c.close()
    return (rows[0] if rows else None) if one else rows


def ex(sql, args=()):
    with write_conn() as c:
        return c.execute(sql, args).lastrowid


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
    WRITE_LOCK.acquire()
    try:
        c = conn()
    except Exception:
        WRITE_LOCK.release()
        raise
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
        # публічна → приватна без токена: генеруємо новий криптографічний invite_token
        c.execute(
            "UPDATE events SET title=?,description=?,event_at=?,max_spots=?,cover_url=?,is_private=?,"
            " invite_token=CASE WHEN ?=1 AND COALESCE(invite_token,'')='' THEN ? ELSE invite_token END"
            " WHERE id=? AND author_id=?",
            (title, description, event_at, max_spots, cover_url, int(is_private), int(is_private),
             secrets.token_urlsafe(24), event_id, author_id))
        c.execute("COMMIT")
        return "ok"
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        c.close()
        WRITE_LOCK.release()


def _tx(fn):
    WRITE_LOCK.acquire()
    try:
        c = conn()
    except Exception:
        WRITE_LOCK.release()
        raise
    try:
        c.execute("BEGIN IMMEDIATE")
        res = fn(c)
        if c.in_transaction:
            c.execute("COMMIT")
        return res
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    finally:
        c.close()
        WRITE_LOCK.release()


def delete_event(event_id, author_id):
    """Атомарне видалення події разом із записами й коментарями."""
    def run(c):
        if not c.execute("SELECT 1 FROM events WHERE id=? AND author_id=?", (event_id, author_id)).fetchone():
            return False
        c.execute("DELETE FROM comments WHERE event_id=?", (event_id,))
        c.execute("DELETE FROM bookings WHERE event_id=?", (event_id,))
        c.execute("DELETE FROM events WHERE id=? AND author_id=?", (event_id, author_id))
        return True
    return _tx(run)


def unbook(event_id, user_id):
    """'ok' | 'past' | 'none'."""
    def run(c):
        ev = c.execute("SELECT event_at FROM events WHERE id=?", (event_id,)).fetchone()
        if ev and ev["event_at"] <= now_iso():
            return "past"
        n = c.execute("DELETE FROM bookings WHERE event_id=? AND user_id=?", (event_id, user_id)).rowcount
        return "ok" if n else "none"
    return _tx(run)


def book(event_id, user_id):
    """Атомарний запис: 'ok' | 'notfound' | 'past' | 'dup' | 'full'."""
    WRITE_LOCK.acquire()
    try:
        c = conn()
    except Exception:
        WRITE_LOCK.release()
        raise
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
        WRITE_LOCK.release()
