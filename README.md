# Лабораторная работа 1: защищенный REST API

Простой backend на Flask с базовыми мерами защиты (OWASP Top 10), JWT-аутентификацией и CI-пайплайном с SAST/SCA.

## Запуск
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app:create_app
export JWT_SECRET_KEY="strong-secret"          # замените в проде
export DEFAULT_ADMIN_PASSWORD="P@ssw0rd!"      # можно переопределить
flask run
```

## Эндпоинты
- `POST /auth/login` — принимает JSON `{"username": "...", "password": "..."}`, возвращает JWT.
- `GET /api/data` — список пользователей (только с валидным JWT).
- `POST /api/notes` — создать заметку, тело `{"body": "text"}` (JWT обязателен).
- `GET /api/notes` — посмотреть заметки (JWT обязателен).
- `GET /healthz` — health check.

## Безопасность
- **Хранилище паролей:** bcrypt (`bcrypt`), пароли никогда не хранятся открыто.
- **JWT:** `flask-jwt-extended`, срок жизни токена 1 час, middleware `@jwt_required`.
- **SQLi:** ORM SQLAlchemy с параметризованными запросами.
- **XSS:** все данные пользователя перед возвратом проходят `html.escape`.
- **Валидация ввода:** проверка JSON-контента и обязательных полей.

## CI/CD
Файл `.github/workflows/ci.yml`:
- Устанавливает зависимости проекта + dev-инструменты.
- **SAST:** `bandit -r .`.
- **SCA:** `safety check -r requirements.txt -r requirements-dev.txt`.

При каждом push/PR проверки запускаются автоматически.
