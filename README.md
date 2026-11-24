# 🎉 Тусовка

Сервіс подій та RSVP: FastAPI + SQLite + Jinja2 + Pico.css.

## Встановлення
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # відредагуйте SECRET_KEY
```

## Змінні оточення
| Змінна | Опис | За замовчуванням |
|---|---|---|
| `SECRET_KEY` | ключ підпису сесійних cookie (обов'язково задайте у проді) | випадковий при кожному старті |
| `PORT` | порт сервера | `8000` |
| `DB_PATH` | шлях до файлу SQLite | `tusovka.db` |
| `COOKIE_SECURE` | `1` — cookie лише по HTTPS | вимкнено |

## Запуск
```bash
export SECRET_KEY=... PORT=8000 DB_PATH=tusovka.db
python -m app.main        # слухає 0.0.0.0:${PORT:-8000}
```
Базу даних створено автоматично під час старту.

## Тести
```bash
pytest
```
Покривають успішні сценарії та атаки: IDOR, приватні події (без токена / з хибним), дублікат запису, гонку за місця, XSS, некоректні вхідні дані, SQLi, CSRF (перевірка Origin).

## Безпека
Параметризовані SQL-запити; запис на подію у `BEGIN IMMEDIATE` + `UNIQUE(event_id,user_id)`; автоекранування Jinja2 (без `|safe`); пароли — PBKDF2 (werkzeug); підписані HttpOnly/SameSite=Lax cookie; CSP та перевірка `Origin` для POST.
