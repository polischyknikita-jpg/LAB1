# Модель загроз SecureLab, ЛР 6

| Елемент | Запис |
|---|---|
| Версія та середовище | review-start b7ace14 (тег v0.5.0), гілка lab/6-hardening-review; SDK 10.0.402; профіль http (Development) і production-like запуск без launch profile; дані з reset/seed, лише тестові акаунти |
| Компоненти в межах огляду | браузерний клієнт (статичні сторінки API), ASP.NET Core API, PostgreSQL у Docker Compose (127.0.0.1), конфігурація, консольні журнали. Redis не використовується |
| Активи | облікові дані й cookie-сеанс; інциденти та право змінювати лише дозволені записи; перехід статусу (triage); дані аудиту; конфігураційні секрети (connection string, SeedUsers:Password) |
| Суб’єкти | анонімний відвідувач; користувач з роллю Reporter; користувач з роллю Analyst; локальний розробник |
| Entry points | GET /api/incidents/, /{id}, /severity-summary, /search; POST /api/incidents; PUT і DELETE /api/incidents/{id}; POST /api/incidents/{id}/triage; GET /api/incident-comments/{id}; POST /api/auth/register, /login, /logout; GET /api/me, /api/auth/session-check, /health; конфігурація; restore пакетів |
| Межі довіри | browser→API, API→PostgreSQL, repository→build, environment→configuration |
| Наявні controls | валідація (ЛР 2); параметризовані запити EF Core (ЛР 2); Identity, cookie-сеанс, rate limiter "login" (ЛР 3); RequireAuthorization на групі incidents, ролі Reporter/Analyst (ЛР 3–4); ресурсна авторизація (ЛР 4); безпечний DOM, CORS Lab05BrowserProbe, X-Content-Type-Options, Referrer-Policy (ЛР 1, 5); antiforgery — ЛР 6 |
| Виключення | зовнішній pentest не виконувався; реального production host, TLS і HSTS немає; історія Git повністю не сканувалася; Redis не входить до огляду |

## Схема меж довіри

```text
browser client (недовірений ввід, автоматична auth cookie)
        │  HTTP (локальний стенд)
        ▼
ASP.NET Core API (validation, authn/authz, antiforgery, logging)
        │  connection string / EF Core
        ▼
PostgreSQL (дані застосунку, 127.0.0.1)

repository + NuGet ──────► build / restore
environment configuration ──► API startup
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Перевірка |
|---|---|---|
| browser→API | змінювальний запит із cookie без request token відхилено без зміни стану | REG-CSRF-01 |
| browser→API | текст користувача не виконується як код | REG-XSS-01 |
| browser→API | JavaScript недозволеного origin не читає відповідь API | REG-CORS-01 |
| browser→API | користувач не отримує й не змінює чужий інцидент | A-* із ЛР 4 |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 із ЛР 2 |
| repository→build | tracked files без реальних credentials; restore не змінює lockfile | git grep (етап 1, п. 3); dotnet restore --locked-mode |
| environment→configuration | у Production не діє Development-конфігурація, reset заборонено | Hosting environment: Production і відмова --reset-database (етап 1, п. 4) |
