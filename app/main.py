import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

from typing import Annotated

from fastapi import FastAPI, Form, Path as PathParam, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import check_password_hash, generate_password_hash

from . import db

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))


def load_secret_key():
    """SECRET_KEY з оточення; інакше — стабільний ключ у файлі .secret_key поруч із БД (спільний для воркерів)."""
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env
    path = Path(os.path.abspath(db.db_path())).parent / ".secret_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(48))
    except FileExistsError:
        pass
    for _ in range(50):  # інший воркер міг щойно створити файл і ще не дописати
        key = path.read_text().strip()
        if key:
            return key
        import time
        time.sleep(0.05)
    raise RuntimeError("Не вдалося прочитати .secret_key")


SECRET_KEY = load_secret_key()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EventId = Annotated[int, PathParam(ge=1, le=2**62)]
DUMMY_HASH = generate_password_hash("dummy-password")


from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax",
                   https_only=os.environ.get("COOKIE_SECURE") == "1", max_age=14 * 86400)


@app.middleware("http")
async def security(request: Request, call_next):
    # CSRF: SameSite=Lax + HttpOnly cookie, зміни стану лише через POST (без перевірки Origin — ламається за proxy)
    nonce = secrets.token_urlsafe(16)
    request.state.nonce = nonce
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; img-src http: https:; style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"script-src 'nonce-{nonce}'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return resp


# ---------- helpers ----------
def current_user(request):
    uid = request.session.get("uid")
    if not isinstance(uid, int):
        return None
    return db.q("SELECT id,email FROM users WHERE id=?", (uid,), one=True)


def safe_next(n):
    """Лише локальні шляхи (захист від open redirect)."""
    n = (n or "").strip()
    if (n.startswith("/") and not n.startswith("//") and len(n) <= 200
            and not re.search(r"[\\\s\x00-\x1f]", n)):
        return n
    return "/"


def login_url(n):
    return "/login?next=" + quote(n, safe="/")


def parse_dt(s):
    """ISO-дата (T/пробіл, секунди, Z, +02:00) → naive локальний datetime без мікросекунд."""
    s = (s or "").strip()
    if not s or len(s) > 40:
        raise ValueError
    if s[-1] in "zZ":
        s = s[:-1] + "+00:00"
    if len(s) > 10 and s[10] in " t":
        s = s[:10] + "T" + s[11:]
    dt = datetime.fromisoformat(s)
    if dt.tzinfo:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.replace(microsecond=0)


def dt_local(v):
    """Значення для <input type="datetime-local">: YYYY-MM-DDTHH:MM."""
    try:
        return parse_dt(str(v)).strftime("%Y-%m-%dT%H:%M")
    except (ValueError, TypeError):
        return ""


templates.env.filters["dtlocal"] = dt_local


def mask_email(v):
    """Не розкриваємо чужі email: «an***@gmail.com» → лише 2 символи локальної частини."""
    local, _, dom = str(v or "").partition("@")
    return (local[:2] + "***") if local else "***"


templates.env.filters["mask"] = mask_email


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"m": msg, "k": kind}


def render(request, name, status=200, **ctx):
    ctx.setdefault("user", current_user(request))
    f = request.session.pop("flash", None)
    if ctx.get("error"):
        f = {"m": ctx["error"], "k": "err"}
    ctx["flash"] = f if isinstance(f, dict) else None
    ctx["nonce"] = getattr(request.state, "nonce", "")
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def err(request, status, msg):
    return render(request, "error.html", status, message=msg)


def get_event(event_id):
    return db.q(
        "SELECT e.*, (SELECT COUNT(*) FROM bookings b WHERE b.event_id=e.id) AS taken,"
        " (SELECT email FROM users u WHERE u.id=e.author_id) AS author_email"
        " FROM events e WHERE e.id=?", (event_id,), one=True)


def session_inv(request):
    inv = request.session.get("inv")
    return [i for i in inv if isinstance(i, int)] if isinstance(inv, list) else []


def visible(request, ev, user, token=None):
    """Приватна подія: лише автор або валідний токен (запам'ятовується в сесії)."""
    if not ev["is_private"]:
        return True
    if user and user["id"] == ev["author_id"]:
        return True
    if token is None:
        token = request.query_params.get("token")
    if token and hmac.compare_digest(token.encode(), ev["invite_token"].encode()):
        inv = session_inv(request)
        if ev["id"] not in inv:
            request.session["inv"] = (inv + [ev["id"]])[-200:]
        return True
    # ідентифікатор + токен у сесії: токен перевіряється при збереженні, тому достатньо id
    return ev["id"] in session_inv(request)


def load_visible(request, event_id, token=None):
    ev = get_event(event_id)
    user = current_user(request)
    if not ev or not visible(request, ev, user, token):
        return None, user
    return ev, user


def parse_event_form(title, description, event_at, max_spots, cover_url):
    title, description, cover_url = title.strip(), description.strip(), cover_url.strip()
    if not title or len(title) > 120:
        return None, "Назва обов'язкова (до 120 символів)."
    if len(description) > 5000:
        return None, "Опис має бути не довшим за 5000 символів."
    try:
        dt = parse_dt(event_at)
    except (ValueError, OverflowError):
        return None, "Невірний формат дати й часу."
    if not 1970 <= dt.year <= 2200:  # минулі дати дозволені (запис на них блокується)
        return None, "Дата події має бути між 1970 і 2200 роками."
    ms = max_spots.strip()
    if not ms.isascii() or not ms.isdigit() or len(ms) > 6 or not 1 <= int(ms) <= 10000:
        return None, "Кількість місць має бути цілим числом від 1 до 10000."
    if cover_url:
        if cover_url.startswith("//"):
            cover_url = "https:" + cover_url
        elif not re.match(r"^https?://", cover_url, re.I):
            # javascript:, data:, vbscript: тощо — відхиляємо; "host:8080/..." — це порт, а не схема
            if re.match(r"^[a-z][a-z0-9+.\-]*:(?!\d)", cover_url, re.I) or "\\" in cover_url:
                return None, "Обкладинка: дозволені лише посилання http:// або https://."
            cover_url = "https://" + cover_url
        try:
            parts = urlsplit(cover_url)
            parts.port
        except ValueError:
            return None, "Обкладинка: некоректне посилання."
        if (len(cover_url) > 500 or not re.match(r"^https?://", cover_url, re.I) or not parts.netloc
                or re.search(r"[\s<>\"'\\\x00-\x1f]", cover_url)):
            return None, "Обкладинка: дозволені лише посилання http:// або https://."
    return dict(title=title, description=description, event_at=dt.isoformat(),
                max_spots=int(ms), cover_url=cover_url or None), None


# ---------- errors ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request, exc):
    msgs = {404: "Сторінку не знайдено.", 403: "Доступ заборонено.", 405: "Метод не дозволено."}
    return render(request, "error.html", exc.status_code, message=msgs.get(exc.status_code, "Помилка."))


@app.exception_handler(sqlite3.OperationalError)
async def db_busy(request, exc):
    return render(request, "error.html", 503, message="Сервіс тимчасово перевантажений, спробуйте ще раз.")


@app.exception_handler(RequestValidationError)
async def val_exc(request, exc):
    return render(request, "error.html", 400, message="Некоректний запит.")


# ---------- auth ----------
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request, next: str = ""):
    return render(request, "auth.html", mode="register", error=None, email="", next=safe_next(next))


@app.post("/register")
def register(request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("")):
    email, nxt = email.strip().lower(), safe_next(next)
    e = None
    if not EMAIL_RE.match(email) or len(email) > 254:
        e = "Невірний email."
    elif not 6 <= len(password) <= 128 or not password.strip():
        e = "Пароль має містити від 6 до 128 символів (не лише пробіли)."
    uid = None if e else db.create_user(email, generate_password_hash(password))
    if not e and uid is None:
        e = "Цей email уже зареєстрований."
    if e:
        return render(request, "auth.html", 400, mode="register", error=e, email=email, next=nxt)
    inv = session_inv(request)
    request.session.clear()
    request.session["uid"] = uid
    if inv:
        request.session["inv"] = inv  # зберегти доступ із запрошення, отриманого до реєстрації
    flash(request, "Реєстрація успішна. Ласкаво просимо!")
    return RedirectResponse(nxt, 303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = ""):
    return render(request, "auth.html", mode="login", error=None, email="", next=safe_next(next))


@app.post("/login")
def login(request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("")):
    email, nxt = email.strip().lower(), safe_next(next)
    u = db.q("SELECT id,password_hash FROM users WHERE email=?", (email,), one=True)
    ok = check_password_hash(u["password_hash"] if u else DUMMY_HASH, password[:128]) and len(password) <= 128
    if not u or not ok:
        return render(request, "auth.html", 400, mode="login", error="Невірний email або пароль.", email=email,
                      next=nxt)
    inv = session_inv(request)
    request.session.clear()
    request.session["uid"] = u["id"]
    if inv:
        request.session["inv"] = inv
    flash(request, "Ви увійшли.")
    return RedirectResponse(nxt, 303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()  # повне очищення: uid, доступи до приватних подій тощо
    flash(request, "Ви вийшли з акаунта.")
    return RedirectResponse("/", 303)


# ---------- pages ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = ""):
    q = q.strip()[:100]
    sql = ("SELECT e.*, (SELECT COUNT(*) FROM bookings b WHERE b.event_id=e.id) AS taken FROM events e"
           " WHERE e.is_private=0 AND e.event_at>?")
    args = [db.now_iso()]
    if q:
        # LOWER() у SQLite не обробляє кирилицю, тому фільтруємо в Python
        rows = [r for r in db.q(sql + " ORDER BY e.event_at", args) if q.casefold() in r["title"].casefold()]
    else:
        rows = db.q(sql + " ORDER BY e.event_at", args)
    return render(request, "index.html", events=rows, q=q)


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    cnt = "(SELECT COUNT(*) FROM bookings b WHERE b.event_id=e.id) AS taken"
    created = db.q(f"SELECT e.*, {cnt} FROM events e WHERE e.author_id=? ORDER BY e.event_at", (user["id"],))
    joined = db.q(f"SELECT e.*, {cnt} FROM events e JOIN bookings k ON k.event_id=e.id AND k.user_id=?"
                  " ORDER BY e.event_at", (user["id"],))
    return render(request, "profile.html", created=created, joined=joined, now=db.now_iso())


@app.get("/events/new", response_class=HTMLResponse)
def new_form(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", 303)
    return render(request, "form.html", ev=None, error=None, action="/events/new")


@app.post("/events/new")
def create(request: Request, title: str = Form(""), description: str = Form(""), event_at: str = Form(""),
           max_spots: str = Form(""), cover_url: str = Form(""), is_private: str = Form("")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    vals, e = parse_event_form(title, description, event_at, max_spots, cover_url)
    if e:
        return render(request, "form.html", 400, ev=dict(title=title, description=description, event_at=event_at,
                      max_spots=max_spots, cover_url=cover_url, is_private=bool(is_private)),
                      error=e, action="/events/new")
    eid = db.create_event(user["id"], vals["title"], vals["description"], vals["event_at"], vals["max_spots"],
                          vals["cover_url"], bool(is_private))
    flash(request, "Подію створено!" + (" Скопіюйте посилання-запрошення нижче." if is_private else ""))
    return RedirectResponse(f"/events/{eid}", 303)


@app.get("/events/{event_id}", response_class=HTMLResponse)
def event_page(request: Request, event_id: EventId, token: str = ""):
    ev, user = load_visible(request, event_id, token)
    if not ev:
        return err(request, 404, "Сторінку не знайдено.")
    if "token" in request.query_params:
        # доступ збережено в сесії — прибираємо секретний токен з URL (історія, Referer, логи)
        return RedirectResponse(f"/events/{event_id}", 303)
    is_author = bool(user and user["id"] == ev["author_id"])
    booked = bool(user and db.q("SELECT 1 FROM bookings WHERE event_id=? AND user_id=?",
                                (event_id, user["id"]), one=True))
    comments = db.q("SELECT c.body,c.created_at,u.email FROM comments c JOIN users u ON u.id=c.user_id"
                    " WHERE c.event_id=? ORDER BY c.id", (event_id,))
    participants = db.q("SELECT u.email FROM bookings b JOIN users u ON u.id=b.user_id WHERE b.event_id=?"
                        " ORDER BY b.id", (event_id,)) if is_author else None
    return render(request, "event.html", ev=ev, is_author=is_author, booked=booked, comments=comments,
                  login_next=login_url(f"/events/{event_id}"),
                  participants=participants, past=ev["event_at"] <= db.now_iso(),
                  invite_url=str(request.url_for("event_page", event_id=ev["id"])) + "?token=" + ev["invite_token"]
                  if is_author and ev["is_private"] else None)


def author_event(request, event_id):
    """Повертає (event, user, error_response). Невидима приватна/неіснуюча → 404 (навіть гостю), гість → /login,
    не-автор → 403."""
    ev, user = load_visible(request, event_id)
    if not ev:
        return None, user, err(request, 404, "Подію не знайдено.")
    if not user:
        return None, None, RedirectResponse(login_url(f"/events/{event_id}"), 303)
    if ev["author_id"] != user["id"]:
        return None, user, err(request, 403, "Лише автор може виконати цю дію.")
    return ev, user, None


@app.get("/events/{event_id}/participants", response_class=HTMLResponse)
def participants(request: Request, event_id: EventId):
    ev, user, bad = author_event(request, event_id)
    if bad:
        return bad
    rows = db.q("SELECT u.email,b.created_at FROM bookings b JOIN users u ON u.id=b.user_id WHERE b.event_id=?"
                " ORDER BY b.id", (event_id,))
    return render(request, "error.html", title=f"Учасники «{ev['title']}»", items=[r["email"] for r in rows],
                  message=None if rows else "Ще ніхто не записався.", back=f"/events/{event_id}")


@app.get("/events/{event_id}/edit", response_class=HTMLResponse)
def edit_form(request: Request, event_id: EventId):
    ev, user, bad = author_event(request, event_id)
    if bad:
        return bad
    return render(request, "form.html", ev=dict(ev), error=None, action=f"/events/{event_id}/edit")


@app.post("/events/{event_id}/edit")
def edit(request: Request, event_id: EventId, title: str = Form(""), description: str = Form(""),
         event_at: str = Form(""), max_spots: str = Form(""), cover_url: str = Form(""), is_private: str = Form("")):
    ev, user, bad = author_event(request, event_id)
    if bad:
        return bad
    form = dict(title=title, description=description, event_at=event_at, max_spots=max_spots,
                cover_url=cover_url, is_private=bool(is_private))
    vals, e = parse_event_form(title, description, event_at, max_spots, cover_url)
    if not e:
        r = db.update_event(event_id, user["id"], vals["title"], vals["description"], vals["event_at"],
                            vals["max_spots"], vals["cover_url"], bool(is_private))
        if r == "forbidden":
            return err(request, 403, "Лише автор може виконати цю дію.")
        if r == "notfound":
            return err(request, 404, "Подію не знайдено.")
        if r == "too_few":
            e = f"Місць не може бути менше, ніж уже записалося учасників ({ev['taken']})."
        else:
            flash(request, "Зміни збережено.")
            return RedirectResponse(f"/events/{event_id}", 303)
    return render(request, "form.html", 400, ev=form, error=e, action=f"/events/{event_id}/edit")


@app.post("/events/{event_id}/delete")
def delete(request: Request, event_id: EventId):
    ev, user, bad = author_event(request, event_id)
    if bad:
        return bad
    db.delete_event(event_id, user["id"])
    flash(request, "Подію видалено.")
    return RedirectResponse("/profile", 303)


@app.post("/events/{event_id}/join")
def join(request: Request, event_id: EventId):
    ev, user = load_visible(request, event_id)
    if not ev:
        return err(request, 404, "Подію не знайдено.")
    if not user:
        return RedirectResponse(login_url(f"/events/{event_id}"), 303)
    r = db.book(event_id, user["id"])
    msgs = {"ok": "Ви записані! До зустрічі 🎉", "dup": "Ви вже записані.",
            "full": "На жаль, вільних місць немає."}
    if r == "notfound":
        return err(request, 404, "Подію не знайдено.")
    if r == "past":
        return err(request, 400, "Подія вже відбулася — запис неможливий.")
    flash(request, msgs[r], "ok" if r == "ok" else "err")
    return RedirectResponse(f"/events/{event_id}", 303)


@app.post("/events/{event_id}/leave")
def leave(request: Request, event_id: EventId):
    ev, user = load_visible(request, event_id)
    if not ev:
        return err(request, 404, "Подію не знайдено.")
    if not user:
        return RedirectResponse(login_url(f"/events/{event_id}"), 303)
    r = db.unbook(event_id, user["id"])
    msgs = {"ok": "Запис скасовано.", "past": "Подія вже минула — скасування неможливе.", "none": "Ви не були записані."}
    flash(request, msgs[r], "ok" if r == "ok" else "err")
    return RedirectResponse(f"/events/{event_id}", 303)


@app.post("/events/{event_id}/comments")
def comment(request: Request, event_id: EventId, body: str = Form("")):
    ev, user = load_visible(request, event_id)
    if not ev:
        return err(request, 404, "Подію не знайдено.")
    if not user:
        return RedirectResponse(login_url(f"/events/{event_id}"), 303)
    body = body.strip()
    if not body or len(body) > 1000:
        return err(request, 400, "Коментар має містити від 1 до 1000 символів.")
    db.ex("INSERT INTO comments(event_id,user_id,body) VALUES(?,?,?)", (event_id, user["id"], body))
    flash(request, "Коментар додано.")
    return RedirectResponse(f"/events/{event_id}", 303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
