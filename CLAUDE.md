# Project: «Тусовка» (Event & RSVP Web Service)
Repo: `git@github.com:DZK678/contest.git`

## Token & Output Discipline (STRICT)
- Zero chatter: no greetings, no step-by-step narration, no repeating instructions or full files in chat. Output only 1-3 line status updates.
- Keep codebase minimal and flat (max 8-10 files). Use `Edit` diffs instead of rewriting whole files. Do not re-read unchanged files.
- Never install heavy frontend build toolchains (no React/Next/Webpack/Vite).

## Tech Stack & Structure
- Backend: Python 3.11+, FastAPI, SQLite (standard `sqlite3` with WAL mode & transactions), Jinja2 templates, `passlib[bcrypt]` (or `werkzeug.security`), `itsdangerous` signed HTTP-only session cookies.
- Frontend: Server-rendered Jinja2 HTML + clean minimal CSS (Pico.css or Tailwind CDN) + tiny vanilla JS only where needed. All UI labels, errors, and `README.md` MUST be in Ukrainian.
- Layout:
  - `app/main.py` (routes, auth, security middleware)
  - `app/db.py` (SQLite schema, atomic queries, migrations on startup)
  - `app/templates/` (`base.html`, `index.html`, `event.html`, `form.html`, `profile.html`, `auth.html`)
  - `tests/test_app.py` (pytest test suite)
  - `README.md`, `requirements.txt`, `.env.example`, `.gitignore`

## Functional Requirements
1. **Auth**: Register & login with `email` + `password`, logout. Normalize email (`strip().lower()`).
2. **Create Event**: `title`, `description`, `event_at` (ISO datetime), `max_spots` (`int >= 1`), `cover_url` (optional image URL), `is_private` (`bool`). Generate cryptographic `invite_token = secrets.token_urlsafe(24)`.
3. **Home (`/`)**: List upcoming public events (`is_private = 0` AND `event_at > now`) sorted by date, with case-insensitive title search (`?q=`).
4. **Event Page (`/events/{id}`)**: Show details, cover, free spots counter (`max_spots - count`), «Іду» / «Скасувати» button, and comments list + add comment form (logged-in users only).
5. **Author Controls**: Only `event.author_id == current_user.id` can edit, delete the event, or view the registered participants list.
6. **Private Events**: If `is_private = 1`, return `404` unless user is the author OR provides valid `?token=<invite_token>` (store access in session once visited via valid invite link).
7. **Profile (`/profile`)**: Show "Створені мною події" and "Події, на які я записався".

## Security & Reliability Invariants (CRITICAL — Evaluated by Pentesters)
- **No IDOR**: Enforce ownership (`author_id == current_user.id`) on backend for `POST/PUT/DELETE` edit, delete, and participants view. Never trust hidden form fields for `user_id`.
- **Atomic Seat Booking (No Overbooking)**: Perform registration inside `BEGIN IMMEDIATE` SQLite transaction checking `COUNT(*) < max_spots` and `UNIQUE(event_id, user_id)`. Prevent booking past events or `max_spots < current_bookings` on edit.
- **XSS Prevention**: Rely on Jinja2 auto-escaping everywhere (`|safe` is FORBIDDEN). Validate `cover_url` strictly starts with `http://` or `https://` (reject `javascript:` / `data:`).
- **Auth & Input Validation**: Hash passwords with bcrypt/PBKDF2; sign cookies with `SECRET_KEY` (`HttpOnly`, `SameSite=Lax`). Validate non-empty trimmed strings, max lengths, valid future datetime, and `max_spots` bounds (`1..10000`). Return proper 400/403/404 status codes, never 500 on bad user input.
- **SQLi**: Parameterized `?` queries only.

## Deliverables & Verification
- `README.md`: Clear Ukrainian setup/run/test commands + required env vars (`SECRET_KEY`, `PORT`, `DB_PATH`). App must auto-init SQLite DB on startup and bind `0.0.0.0:${PORT:-8000}`.
- `tests/test_app.py`: Single-command `pytest` suite covering happy paths AND attack scenarios: IDOR edit/delete, private event access without/with invalid token, duplicate booking, race-condition/overbooking at capacity, XSS payload escaping, invalid inputs.
- Before finishing: run `pytest`, verify clean git status, commit, and push to `origin main`.