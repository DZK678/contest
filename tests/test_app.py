import os
import re
import tempfile
import threading
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

os.environ["SECRET_KEY"] = "test-secret"
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")

from app import db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(os.environ["DB_PATH"] + ext)
        except FileNotFoundError:
            pass
    db.init_db()


def client(**headers):
    return TestClient(app, follow_redirects=False, headers=headers or {"origin": "http://testserver"})


def future(days=3):
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M")


def signup(email="a@x.com", pw="password123"):
    c = client()
    r = c.post("/register", data={"email": email, "password": pw})
    assert r.status_code == 303
    return c


def mk(c, **kw):
    d = dict(title="Вечірка", description="Опис", event_at=future(), max_spots="5", cover_url="")
    d.update(kw)
    r = c.post("/events/new", data=d)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_auth_happy_and_email_normalization():
    c = signup("  User@X.COM ")
    assert "user@x.com" in c.get("/").text
    c.post("/logout")
    assert "Увійти" in c.get("/").text
    c2 = client()
    assert c2.post("/login", data={"email": "USER@x.com", "password": "password123"}).status_code == 303
    assert c2.post("/login", data={"email": "user@x.com", "password": "bad"}).status_code == 400
    assert client().post("/register", data={"email": "user@x.com", "password": "password123"}).status_code == 400


def test_invalid_register_inputs():
    c = client()
    for e, p in [("", "password123"), ("nomail", "password123"), ("a@b.co", "short"), ("a@b.co", "      "), ("a@b.co", "x" * 200)]:
        assert c.post("/register", data={"email": e, "password": p}).status_code == 400
    assert c.post("/register").status_code == 400


def test_event_flow_search_comment():
    c = signup()
    eid = mk(c, title="Квітнева Вечірка")
    mk(c, title="Інше", event_at=future(5))
    mk(c, title="Приватна", is_private="on")
    idx = c.get("/").text
    assert "Квітнева Вечірка" in idx and "Приватна" not in idx
    assert idx.index("Квітнева") < idx.index("Інше")
    s = c.get("/", params={"q": "квітнева"}).text
    assert "Квітнева" in s and "Інше" not in s
    assert c.post(f"/events/{eid}/join").status_code == 303
    page = c.get(f"/events/{eid}").text
    assert "Вільних місць: 4" in page and "Скасувати" in page
    c.post(f"/events/{eid}/comments", data={"body": "Привіт"})
    assert "Привіт" in c.get(f"/events/{eid}").text
    c.post(f"/events/{eid}/leave")
    assert "Вільних місць: 5" in c.get(f"/events/{eid}").text
    assert "Квітнева" in c.get("/profile").text


def test_comment_requires_login_and_validation():
    c = signup()
    eid = mk(c)
    anon = client()
    assert anon.post(f"/events/{eid}/comments", data={"body": "x"}).status_code == 303
    assert c.post(f"/events/{eid}/comments", data={"body": "  "}).status_code == 400
    assert c.post(f"/events/{eid}/comments", data={"body": "a" * 1001}).status_code == 400


@pytest.mark.parametrize("over", [
    {"title": "  "}, {"title": "x" * 121}, {"description": ""}, {"event_at": "garbage"},
    {"event_at": "2001-01-01T10:00"}, {"max_spots": "0"}, {"max_spots": "10001"}, {"max_spots": "-1"},
    {"max_spots": "abc"}, {"max_spots": "1.5"}, {"cover_url": "javascript:alert(1)"},
    {"cover_url": "data:text/html;base64,AAAA"}, {"cover_url": "ftp://x.com/a.png"},
    {"cover_url": "https://x.com/a b.png"},
])
def test_invalid_event_inputs(over):
    c = signup()
    d = dict(title="T", description="D", event_at=future(), max_spots="5", cover_url="")
    d.update(over)
    assert c.post("/events/new", data=d).status_code == 400
    assert c.post("/events/new", data={}).status_code == 400


def test_idor_edit_delete_participants():
    a = signup("a@x.com")
    eid = mk(a)
    b = signup("b@x.com")
    b.post(f"/events/{eid}/join")
    data = dict(title="Hacked", description="d", event_at=future(), max_spots="5", cover_url="")
    assert b.get(f"/events/{eid}/edit").status_code == 403
    assert b.post(f"/events/{eid}/edit", data=data).status_code == 403
    assert b.post(f"/events/{eid}/delete").status_code == 403
    assert b.get(f"/events/{eid}/participants").status_code == 403
    assert "Керування" not in b.get(f"/events/{eid}").text
    anon = client()
    assert anon.post(f"/events/{eid}/delete").status_code == 303  # на логін, нічого не видалено
    assert db.q("SELECT title FROM events WHERE id=?", (eid,), one=True)["title"] == "Вечірка"
    assert "b@x.com" in a.get(f"/events/{eid}/participants").text
    assert a.post(f"/events/{eid}/edit", data=data).status_code == 303
    assert a.post(f"/events/{eid}/delete").status_code == 303
    assert a.get(f"/events/{eid}").status_code == 404


def test_hidden_user_id_ignored():
    a = signup("a@x.com")
    b = signup("b@x.com")
    eid = mk(a)
    b.post(f"/events/{eid}/join", data={"user_id": "1"})
    assert db.q("SELECT user_id FROM bookings", one=True)["user_id"] == 2


def test_private_event_access():
    a = signup("a@x.com")
    eid = mk(a, is_private="on")
    tok = db.q("SELECT invite_token FROM events WHERE id=?", (eid,), one=True)["invite_token"]
    assert len(tok) >= 32
    assert a.get(f"/events/{eid}").status_code == 200
    b = signup("b@x.com")
    assert b.get(f"/events/{eid}").status_code == 404
    assert b.get(f"/events/{eid}?token=wrong").status_code == 404
    assert b.get(f"/events/{eid}?token=").status_code == 404
    assert client().get(f"/events/{eid}").status_code == 404
    assert b.post(f"/events/{eid}/join").status_code == 404
    assert b.post(f"/events/{eid}/comments", data={"body": "x"}).status_code == 404
    assert b.get(f"/events/{eid}/edit").status_code == 404
    r = b.get(f"/events/{eid}?token={tok}")
    assert r.status_code == 303 and r.headers["location"] == f"/events/{eid}"
    assert b.get(f"/events/{eid}").status_code == 200  # збережено в сесії
    assert b.post(f"/events/{eid}/join").status_code == 303
    assert "Приватна" not in b.get("/").text
    assert b.get(f"/events/{eid}/edit").status_code == 403


def test_duplicate_and_past_booking():
    a = signup()
    eid = mk(a)
    a.post(f"/events/{eid}/join")
    a.post(f"/events/{eid}/join")
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 1
    db.ex("UPDATE events SET event_at=? WHERE id=?", ((datetime.now() - timedelta(days=1)).isoformat(timespec="seconds"), eid))
    b = signup("b@x.com")
    b.post(f"/events/{eid}/join")
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 1
    assert "Іду" not in b.get(f"/events/{eid}").text
    assert eid not in [r["id"] for r in db.q("SELECT id FROM events WHERE event_at>?", (db.now_iso(),))]
    assert "Вечірка" not in b.get("/").text


def test_overbooking_race():
    a = signup()
    eid = mk(a, max_spots="3")
    uids = [db.create_user(f"u{i}@x.com", "h") for i in range(30)]
    results, barrier = [], threading.Barrier(len(uids))

    def go(u):
        barrier.wait()
        results.append(db.book(eid, u))

    ts = [threading.Thread(target=go, args=(u,)) for u in uids]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("ok") == 3 and results.count("full") == 27
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 3


def test_edit_cannot_shrink_below_bookings():
    a = signup()
    eid = mk(a, max_spots="5")
    for i in range(3):
        u = signup(f"u{i}@x.com")
        u.post(f"/events/{eid}/join")
    d = dict(title="T", description="D", event_at=future(), max_spots="2", cover_url="")
    assert a.post(f"/events/{eid}/edit", data=d).status_code == 400
    d["max_spots"] = "3"
    assert a.post(f"/events/{eid}/edit", data=d).status_code == 303
    assert "Вільних місць: 0" in a.get(f"/events/{eid}").text


def test_xss_escaped():
    p = "<script>alert(1)</script>"
    a = signup()
    eid = mk(a, title=p, description=p, cover_url="https://x.com/a.png")
    a.post(f"/events/{eid}/comments", data={"body": p})
    for url in (f"/events/{eid}", "/", "/profile"):
        t = a.get(url).text
        assert p not in t
    assert "&lt;script&gt;" in a.get(f"/events/{eid}").text
    assert "|safe" not in "".join(open(os.path.join("app/templates", f)).read() for f in os.listdir("app/templates"))


def test_bad_ids_and_methods_no_500():
    c = signup()
    for u in ("/events/abc", "/events/99999", "/events/-1", "/events/99999999999999999999999"):
        assert c.get(u).status_code in (400, 404)
    assert c.post("/events/99999/join").status_code == 404
    assert c.post("/events/abc/delete").status_code in (400, 404)
    assert c.get("/events/99999/edit").status_code == 404


def test_sqli_search_and_login():
    c = signup()
    mk(c)
    assert c.get("/", params={"q": "' OR 1=1 --"}).status_code == 200
    assert client().post("/login", data={"email": "' OR '1'='1", "password": "x"}).status_code == 400


def test_csrf_origin_and_cookie_flags():
    c = client()
    r = c.post("/register", data={"email": "q@x.com", "password": "password123"})
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=lax" in sc
    assert c.post("/logout", headers={"origin": "https://evil.com"}).status_code == 403
    assert c.post("/logout", headers={"origin": "http://testserver"}).status_code == 303


def test_forged_cookie_rejected():
    c = client()
    c.cookies.set("session", "eyJ1aWQiOiAxfQ==.abc.def")
    assert "Увійти" in c.get("/").text
    assert c.get("/profile").status_code == 303


def test_csrf_foreign_origin_or_referer_rejected():
    c = signup()
    raw = TestClient(app, follow_redirects=False, cookies=c.cookies)
    assert raw.post("/logout", headers={"referer": "https://evil.com/x"}).status_code == 403
    assert raw.post("/logout", headers={"origin": "null"}).status_code == 403
    assert raw.post("/logout", headers={"origin": "http://testserver.evil.com"}).status_code == 403
    assert raw.post("/events/new", headers={"origin": "https://evil.com"}, data={"title": "x"}).status_code == 403
    assert raw.post("/logout", headers={"referer": "http://testserver/events/1"}).status_code == 303
    assert client().post("/register", headers={"origin": ""}, data={}).status_code in (400, 403)


def test_private_post_endpoints_and_search_leak():
    a = signup("a@x.com")
    eid = mk(a, title="Секретна тусовка", is_private="on")
    a.post(f"/events/{eid}/comments", data={"body": "таємний коментар"})
    b = signup("b@x.com")
    for path, data in [("join", None), ("leave", None), ("comments", {"body": "x"}), ("delete", None),
                       ("edit", {"title": "x"})]:
        assert b.post(f"/events/{eid}/{path}", data=data).status_code == 404, path
    assert b.get(f"/events/{eid}/participants").status_code == 404
    assert b.post(f"/events/{eid}/join?token=wrong").status_code == 404
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 0
    assert db.q("SELECT COUNT(*) c FROM comments", one=True)["c"] == 1
    for q in ("Секретна", "секретна", "тусовка", ""):
        assert f"/events/{eid}" not in b.get("/", params={"q": q}).text
        assert f"/events/{eid}" not in client().get("/", params={"q": q}).text


def test_participants_only_author_even_with_invite():
    a = signup("a@x.com")
    eid = mk(a, is_private="on")
    tok = db.q("SELECT invite_token FROM events WHERE id=?", (eid,), one=True)["invite_token"]
    b = signup("guest@x.com")
    b.get(f"/events/{eid}?token={tok}")
    b.post(f"/events/{eid}/join")
    page = b.get(f"/events/{eid}").text
    assert "Учасники" not in page and "guest@x.com" in page  # лише у шапці (власний email)
    assert page.count("guest@x.com") == 1
    assert b.get(f"/events/{eid}/participants").status_code == 403
    assert "guest@x.com" in a.get(f"/events/{eid}/participants").text
    pub = mk(a)
    c = signup("c@x.com")
    assert c.get(f"/events/{pub}/participants").status_code == 403
    assert client().get(f"/events/{pub}/participants").status_code == 303


def test_sqlite_pragmas_and_cascade_schema():
    c = db.conn()
    try:
        assert c.execute("PRAGMA busy_timeout").fetchone()[0] == 15000
        assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        for t in ("events", "bookings", "comments"):
            fks = c.execute(f"PRAGMA foreign_key_list({t})").fetchall()
            assert fks and all(fk["on_delete"] == "CASCADE" for fk in fks)
    finally:
        c.close()


def test_delete_event_with_bookings_and_comments():
    a = signup("a@x.com")
    eid = mk(a)
    for i in range(3):
        u = signup(f"u{i}@x.com")
        u.post(f"/events/{eid}/join")
        u.post(f"/events/{eid}/comments", data={"body": f"коментар {i}"})
    r = a.post(f"/events/{eid}/delete")
    assert r.status_code == 303
    for t in ("events", "bookings", "comments"):
        assert db.q(f"SELECT COUNT(*) c FROM {t}", one=True)["c"] == 0
    assert "Подію видалено" in a.get("/profile").text
    # каскад на рівні БД теж працює
    eid2 = mk(a)
    signup("z@x.com").post(f"/events/{eid2}/comments", data={"body": "x"})
    db.ex("DELETE FROM events WHERE id=?", (eid2,))
    assert db.q("SELECT COUNT(*) c FROM comments", one=True)["c"] == 0


def test_migration_adds_cascade_to_legacy_db():
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(os.environ["DB_PATH"] + ext)
        except FileNotFoundError:
            pass
    old = db.SCHEMA.replace(" ON DELETE CASCADE", "")
    c = db.conn()
    c.executescript(old)
    c.execute("INSERT INTO users(email,password_hash) VALUES('o@x.com','h')")
    c.execute("INSERT INTO events(author_id,title,description,event_at,max_spots,invite_token)"
              " VALUES(1,'Old','d','2099-01-01T10:00:00',5,'tok')")
    c.execute("INSERT INTO bookings(event_id,user_id) VALUES(1,1)")
    c.execute("INSERT INTO comments(event_id,user_id,body) VALUES(1,1,'hi')")
    c.close()
    db.init_db()
    db.init_db()  # ідемпотентно
    assert db.q("SELECT title FROM events", one=True)["title"] == "Old"
    assert db.q("SELECT COUNT(*) c FROM comments", one=True)["c"] == 1
    db.ex("DELETE FROM events WHERE id=1")
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 0
    assert db.q("SELECT COUNT(*) c FROM comments", one=True)["c"] == 0
    assert db.q("SELECT name FROM sqlite_master WHERE name='idx_events_at'", one=True)


def test_http_race_for_last_seat():
    a = signup("a@x.com")
    eid = mk(a, max_spots="1")
    users = [signup(f"r{i}@x.com") for i in range(12)]
    codes, barrier = [], threading.Barrier(len(users))

    def go(cl):
        barrier.wait()
        codes.append(cl.post(f"/events/{eid}/join").status_code)

    ts = [threading.Thread(target=go, args=(u,)) for u in users]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(code == 303 for code in codes), codes  # жодних 500 / database is locked
    assert db.q("SELECT COUNT(*) c FROM bookings WHERE event_id=?", (eid,), one=True)["c"] == 1
    assert "Вільних місць: 0" in a.get(f"/events/{eid}").text


@pytest.mark.parametrize("when", ["2030-06-01T10:00:00+02:00", "2030-06-01T10:00:00Z", "2030-06-01T10:00",
                                  "2030-06-01T10:00:00.123456", "2030-06-01"])
def test_datetime_formats_no_500(when):
    c = signup()
    eid = mk(c, event_at=when)
    ev = db.q("SELECT event_at FROM events WHERE id=?", (eid,), one=True)["event_at"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ev)  # єдиний naive-формат
    assert c.get("/").status_code == 200 and c.get(f"/events/{eid}").status_code == 200
    assert c.post(f"/events/{eid}/join").status_code == 303


@pytest.mark.parametrize("over", [
    {"description": "   \n\t "}, {"title": "\u00a0 \t"}, {"description": "x" * 5001},
    {"event_at": "9" * 5000}, {"event_at": "2030-13-40T10:00"}, {"event_at": "1999-01-01T10:00:00+14:00"},
    {"max_spots": "١٢"}, {"max_spots": "9" * 50}, {"max_spots": " "}, {"cover_url": "https://" + "a" * 600},
    {"cover_url": "https://x.com/\"onerror=\"alert(1)"}, {"cover_url": "JaVaScRiPt:alert(1)"},
    {"cover_url": "//evil.com/a.png"}, {"cover_url": "https://"},
])
def test_more_invalid_inputs_400(over):
    c = signup()
    d = dict(title="T", description="D", event_at=future(), max_spots="5", cover_url="")
    d.update(over)
    r = c.post("/events/new", data=d)
    assert r.status_code == 400 and 'class="flash err"' in r.text


def test_edit_shrink_message_and_past_leave():
    a = signup()
    eid = mk(a, max_spots="5")
    for i in range(2):
        signup(f"u{i}@x.com").post(f"/events/{eid}/join")
    d = dict(title="T", description="D", event_at=future(), max_spots="1", cover_url="")
    r = a.post(f"/events/{eid}/edit", data=d)
    assert r.status_code == 400 and "менше, ніж уже записалося учасників (2)" in r.text
    assert db.q("SELECT max_spots FROM events WHERE id=?", (eid,), one=True)["max_spots"] == 5
    b = client()
    b.post("/login", data={"email": "u0@x.com", "password": "password123"})
    db.ex("UPDATE events SET event_at='2000-01-01T00:00:00' WHERE id=?", (eid,))
    assert b.post(f"/events/{eid}/leave").status_code == 303
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 2


def test_flash_messages_and_ux():
    c = client()
    c.post("/register", data={"email": "f@x.com", "password": "password123"})
    r = c.get("/")
    assert "Реєстрація успішна" in r.text
    nonce = re.search(r'<script nonce="([^"]+)"', r.text).group(1)
    assert f"'nonce-{nonce}'" in r.headers["content-security-policy"]
    eid = mk(c, is_private="on", cover_url="https://broken.invalid/x.png")
    page = c.get(f"/events/{eid}").text
    assert "Подію створено" in page
    assert 'data-copy="invite-url"' in page and "?token=" in page
    assert 'class="cover"' in page and "cover-fallback" in page
    assert "Подію створено" not in c.get(f"/events/{eid}").text  # flash одноразовий
    c.post(f"/events/{eid}/join")
    assert "Ви записані" in c.get(f"/events/{eid}").text
    c.post(f"/events/{eid}/leave")
    assert "Запис скасовано" in c.get(f"/events/{eid}").text
    d = dict(title="Нове", description="D", event_at=future(), max_spots="5", cover_url="")
    c.post(f"/events/{eid}/edit", data=d)
    assert "Зміни збережено" in c.get(f"/events/{eid}").text
    assert "нічого не знайдено" in c.get("/", params={"q": "zzz"}).text
    assert "Будьте першим" in c.get(f"/events/{eid}").text
    csp = r.headers.get("content-security-policy", "")
    assert "script-src 'nonce-" in csp and "unsafe-inline" not in csp


def test_no_origin_post_allowed_and_referrer_policy():
    raw = TestClient(app, follow_redirects=False)  # як requests/httpx: без Origin і Referer
    assert raw.post("/register", data={"email": "n@x.com", "password": "secret"}).status_code == 303
    eid = mk(raw)
    assert raw.post(f"/events/{eid}/join").status_code == 303
    r = raw.get(f"/events/{eid}")
    assert r.headers["referrer-policy"] == "no-referrer"
    assert raw.get("/").headers["referrer-policy"] == "no-referrer"


def test_invite_token_redirect_and_logout_clears_session():
    a = signup("a@x.com")
    eid = mk(a, is_private="on")
    tok = db.q("SELECT invite_token FROM events WHERE id=?", (eid,), one=True)["invite_token"]
    g = client()  # гість без акаунта
    r = g.get(f"/events/{eid}", params={"token": tok})
    assert r.status_code == 303 and r.headers["location"] == f"/events/{eid}" and tok not in r.headers["location"]
    page = g.get(f"/events/{eid}")
    assert page.status_code == 200 and tok not in page.text
    assert g.get(f"/events/{eid}", params={"token": tok[:-1] + "A"}).status_code in (303, 200)  # доступ уже в сесії
    assert client().get(f"/events/{eid}", params={"token": tok[:-1] + "A"}).status_code == 404
    # після входу доступ із запрошення зберігається, після logout — зникає
    signup("b@x.com")
    g.post("/login", data={"email": "b@x.com", "password": "password123", "next": f"/events/{eid}"})
    assert g.get(f"/events/{eid}").status_code == 200
    assert g.post("/logout").status_code == 303
    assert g.get(f"/events/{eid}").status_code == 404


def test_login_next_redirect_safe():
    signup("n@x.com")
    c = client()
    eid = mk(signup("a@x.com"))
    page = c.get(f"/events/{eid}").text
    assert f'href="/login?next=/events/{eid}"' in page
    assert f'value="/events/{eid}"' in c.get("/login", params={"next": f"/events/{eid}"}).text
    r = c.post("/login", data={"email": "n@x.com", "password": "password123", "next": f"/events/{eid}"})
    assert r.headers["location"] == f"/events/{eid}"
    for bad in ("//evil.com", "https://evil.com", "/\\evil.com", "javascript:alert(1)"):
        r = client().post("/login", data={"email": "n@x.com", "password": "password123", "next": bad})
        assert r.headers["location"] == "/", bad
    r = client().post("/register", data={"email": "q@x.com", "password": "secret", "next": f"/events/{eid}"})
    assert r.headers["location"] == f"/events/{eid}"
    assert client().post(f"/events/{eid}/join").headers["location"] == f"/login?next=/events/{eid}"


def test_login_error_does_not_reveal_email():
    signup("e@x.com")
    r1 = client().post("/login", data={"email": "e@x.com", "password": "wrong-pass"})
    r2 = client().post("/login", data={"email": "nobody@x.com", "password": "wrong-pass"})
    assert r1.status_code == r2.status_code == 400
    assert "Невірний email або пароль" in r1.text and "Невірний email або пароль" in r2.text


@pytest.mark.parametrize("when", ["2030-06-01 10:00", "2030-06-01 10:00:00", "2030-06-01T10:00:00Z",
                                  "2030-06-01T10:00:00+02:00", "2030-06-01t10:00z"])
def test_edit_form_datetime_local_format(when):
    c = signup()
    eid = mk(c, event_at=when)
    html = c.get(f"/events/{eid}/edit").text
    v = re.search(r'name="event_at" value="([^"]*)"', html).group(1)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", v), v
    d = dict(title="T", description="D", event_at=v, max_spots="5", cover_url="")
    assert c.post(f"/events/{eid}/edit", data=d).status_code == 303
    assert c.get(f"/events/{eid}/edit").text.count(f'value="{v}"') == 1


def test_public_to_private_generates_token():
    c = signup()
    eid = mk(c)
    db.ex("UPDATE events SET invite_token='' WHERE id=?", (eid,))
    d = dict(title="T", description="D", event_at=future(), max_spots="5", cover_url="", is_private="on")
    assert c.post(f"/events/{eid}/edit", data=d).status_code == 303
    ev = db.q("SELECT is_private, invite_token FROM events WHERE id=?", (eid,), one=True)
    assert ev["is_private"] == 1 and len(ev["invite_token"]) >= 32
    assert client().get(f"/events/{eid}").status_code == 404


def test_full_event_shows_no_spots():
    a = signup("a@x.com")
    eid = mk(a, max_spots="1")
    b = signup("b@x.com")
    b.post(f"/events/{eid}/join")
    pb = b.get(f"/events/{eid}").text
    assert "Скасувати" in pb and "Місць немає" not in pb
    pc = signup("c@x.com").get(f"/events/{eid}").text
    assert "Місць немає" in pc and ">Іду<" not in pc and f"/events/{eid}/join" not in pc


def test_profile_lists_with_marks():
    a = signup("a@x.com")
    pub = mk(a, title="Публічна")
    prv = mk(a, title="Закрита", is_private="on")
    old = mk(a, title="Стара")
    for e in (pub, prv, old):
        a.post(f"/events/{e}/join")
    db.ex("UPDATE events SET event_at='2000-01-01T00:00:00' WHERE id=?", (old,))
    html = a.get("/profile").text
    created, joined = html.split("Події, на які я записався")
    for part in (created, joined):
        assert "Публічна" in part and "Закрита" in part and "Стара" in part
        assert part.count("🔒 приватна") == 1 and part.count("минула") == 1 and part.count("майбутня") == 2


def test_concurrent_writes_no_errors():
    a = signup("a@x.com")
    eid = mk(a, max_spots="10000")
    users = [signup(f"w{i}@x.com") for i in range(20)]
    codes, barrier = [], threading.Barrier(len(users))

    def go(cl):
        barrier.wait()
        codes.append(cl.post(f"/events/{eid}/join").status_code)
        codes.append(cl.post(f"/events/{eid}/comments", data={"body": "привіт"}).status_code)

    ts = [threading.Thread(target=go, args=(u,)) for u in users]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert codes.count(303) == 40, codes
    assert db.q("SELECT COUNT(*) c FROM bookings", one=True)["c"] == 20
    assert db.q("SELECT COUNT(*) c FROM comments", one=True)["c"] == 20


def test_db_dir_autocreated(tmp_path, monkeypatch):
    p = tmp_path / "nested" / "dir" / "x.db"
    monkeypatch.setenv("DB_PATH", str(p))
    db.init_db()
    assert p.exists()
