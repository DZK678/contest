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
Базу даних створено автоматично під час старту (WAL, `busy_timeout=5000`, `foreign_keys=ON`; старі БД автоматично мігруються на `ON DELETE CASCADE`).

## Тести
```bash
pytest
```
Покривають успішні сценарії та атаки: IDOR (редагування/видалення/учасники), приватні події (GET і POST «Іду»/«Скасувати»/коментар без токена чи з хибним, витік у пошуку), дублікат запису, багатопотокову гонку за останнє місце, видалення події з учасниками й коментарями, міграцію CASCADE, XSS, некоректні дані й формати дат (без 500), SQLi, CSRF (без Origin/Referer → 403), flash-повідомлення.

## Безпека
Параметризовані SQL-запити; запис на подію у `BEGIN IMMEDIATE` + `UNIQUE(event_id,user_id)`; автоекранування Jinja2 (без `|safe`); пароли — PBKDF2 (werkzeug); підписані HttpOnly/SameSite=Lax cookie; CSP з nonce (без `unsafe-inline`); CSRF — кожен POST повинен мати `Origin` або `Referer`, що збігається з `Host`, інакше 403.

## Зручність
Flash-повідомлення після дій, кнопка «Копіювати» для посилання-запрошення приватної події, охайні порожні стани, заглушка замість битої обкладинки.
