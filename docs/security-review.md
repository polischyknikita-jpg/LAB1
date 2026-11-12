# Security review SecureLab, ЛР 6

Рівень: добрий («Добре»). Commit початку огляду (review-start): b7ace148062039f2b722a596915ada77052ec0ca (тег v0.5.0). Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата: 12–13.11.2026; SDK 10.0.402; профілі: http (Development) і production-like без launch profile; клієнт: Chrome, PowerShell 5.1, curl.exe.

## 1. Executive summary
Перевірено власний SecureLab (baseline 2-A) після ЛР 5: межі довіри, секрети й конфігурацію, безпечні помилки, браузерні заголовки, CORS, cookie, CSRF, rate limiting, залежності, журнали й аудит. Реалізовано antiforgery для всіх cookie-автентифікованих mutation (REG-CSRF-01), обмеження пошуку з окремими partitions, подію аудиту дозволеного triage, автоматизовано S-02. Зафіксовано й виправлено 2 знахідки: F-02 (P1, пошук обходив матрицю доступу) і F-01 (P3, заголовки безпеки зникали на 500). Фінальний прогін: `dotnet test SecureLab.sln -c Release` → 36/36. Головні залишкові ризики: локальний HTTP без TLS/HSTS, in-memory limiter, login-CSRF для анонімного входу.

## 2. Scope та exclusions
У межах: усі поточні tracked files гілки lab/6-hardening-review; API, статичний клієнт, PostgreSQL у Docker Compose (127.0.0.1), конфігурація, консольні журнали. Історія Git: переглянуто лише історію infra/compose.yaml і appsettings.Development.json (лише 405e99a Initial starter project); решту історії, stash, клони й зовнішній CI не перевірено. Виключено: зовнішній pentest, реальний production host, TLS termination, reverse proxy, Redis.

## 3. System overview і trust boundaries
Див. docs/threat-model.md. Межі → тест: browser→API — REG-CSRF-01, REG-XSS-01, REG-CORS-01, A-* ЛР 4, REG-SEARCH-01; API→PostgreSQL — S-02; repository→build — git grep (101 → 113 збігів, класифіковано), `dotnet restore --locked-mode`; environment→configuration — Hosting environment: Production і відмова `--reset-database`.

## 4. Methodology та test environment
Відомий стан: `dotnet run --project src/SecureLab.Api -- --reset-database` (лише Development, Database:AllowReset). БД: локальний PostgreSQL з infra/compose.yaml, порт 54329. Production-like: `..\lr06-resources\commands\Production.ps1 -Mode normal|broken` (broken — порт 54399). Пароль seed — змінна SeedUsers__Password поза Git. Сеанси: alice/bob/morgan у Chrome (звичайне вікно й інкогніто). Коміти огляду: 5a5ab95 (antiforgery), ccf5099 (search limiter), f10001b (audit), da36ed1 (S-02), 1bb17d2 (F-01), a083a81 (F-02).

## 5. Findings summary
| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Retest |
|---|---|---|---|---|---|---|
| F-02 | конфіденційність чужих інцидентів | високий | висока: публічний GET | P1 | Fixed a083a81 | REG-SEARCH-01 |
| F-01 | заголовки на всіх класах відповідей | низький | середня: потрібна 500 | P3 | Fixed 1bb17d2 | Production broken curl |

## 6. Detailed findings
- docs/findings/F-01-error-path-headers.md
- docs/findings/F-02-search-access-control.md

## 7. Regression results
| ID | Властивість | Тест / процедура | Результат |
|---|---|---|---|
| T-02, T-03 | server validation | Post_WithInvalidDto_Returns400WithFieldErrors; Post_WithDuplicateActiveTitle_Returns409 | pass |
| S-02 | SQLi | S02_Search_WithSqlMetacharacters_IsLiteral_AndUnknownSortBy_Returns400 | pass |
| A-01…A-07 ЛР 3 | authentication | AuthenticationSecurityTests.* | pass |
| A-02…A-12 ЛР 4 | authorization / IDOR | Lab04AuthorizationTests.*; IncidentOwnershipTests.* | pass |
| REG-SEARCH-01 | пошук за матрицею доступу | SearchAuthorizationTests.RegSearch01_* | pass |
| REG-XSS-01 | text не виконується як code | ручна процедура browser-lab; ClientScript_DoesNotUseDangerousInnerHtmlSink | pass |
| REG-CORS-01 | exact origin | ручна процедура 4173/4174 + curl з Origin | pass |
| REG-CSRF-01 | token pair required, стан не змінено | RegCsrf01_UpdateIncident_WithoutOrInvalidToken_Rejected_WithToken_Succeeds | pass |
| rate limit login (ЛР 3) | quota/429/відновлення | Login_OverLimit_Returns429ForAnyUser_ThenRecoversAfterWindow | pass |
| rate limit search (ЛР 6) | 2 partitions, quota, 429, відновлення | Search_OverQuota_Returns429_OtherUserUnaffected_ThenRecovers | pass |

Команда: `dotnet test SecureLab.sln -c Release` після reset → 36/36. Фінальний commit і результат на merge HEAD — у metadata PDF.

## 8. Hardening controls
| Control | Ризик | Перевірка | Межа |
|---|---|---|---|
| X-Content-Type-Options, Referrer-Policy, CSP default-src 'self'; frame-ancestors 'none' | MIME sniffing, витік Referer, clickjacking | Development/Chrome: 200, 400, 404; Production/curl: 200, 404, 500 | не замінює безпечний DOM і авторизацію |
| CORS Lab05BrowserProbe (лише Development, exact origin 4173, GET, credentials) | читання відповіді чужим origin | REG-CORS-01 | не захищає від надсилання запиту, не є CSRF-захистом |
| Auth cookie: HttpOnly, SameSite=Lax, Secure у Production | крадіжка cookie скриптом, частина cross-site запитів | DevTools Application → Cookies | Lax не захищає same-site сторінки |
| Antiforgery (X-CSRF-TOKEN, cookie securelab-af HttpOnly Strict), AntiforgeryFilter | CSRF на cookie-автентифіковані mutation | REG-CSRF-01; ручна перевірка клієнта | login/register поза периметром токена |
| Login limiter: IP, 10/60 с | перебір паролів | 11 спроб → 429, відновлення після 65 с, однаковий 429 для невідомого акаунта | спільний IP за NAT, in-memory |
| Search limiter: user id (IP для анонімів), 5/30 с | зловживання пошуком | alice 6-й → 429, bob → 200, відновлення | in-memory, один instance |
| Exception handler + Problem Details з traceId | витік деталей помилки | Production broken: 500 лише title і traceId, TraceId у журналі | — |
| HTTPS/HSTS | перехоплення трафіку | конфігурація: лише http-профіль, UseHsts відсутній | реальний TLS не тестувався; loopback у ExcludedHosts |

Development/Production: OpenAPI лише в Development (Production /openapi/v1.json → 404); CORS-політика лише в Development; reset БД заборонено в Production; auth cookie Secure=Always лише в Production.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | POST /api/incidents | Lab02Endpoints; browser-lab.js, auth-lab.js | створення інциденту | так | так | explicit | REG-CSRF-01 (filter), ручна перевірка |
| SC-02 | PUT /api/incidents/{id} | IncidentEndpoints; DISCREPANCY: немає client call | оновлення | так | так | explicit | REG-CSRF-01 |
| SC-03 | DELETE /api/incidents/{id} | IncidentEndpoints; DISCREPANCY | видалення | так | так | explicit | A04_Delete_* з токеном |
| SC-04 | POST /api/incidents/{id}/triage | IncidentEndpoints; DISCREPANCY | Incident.Status | так | так | explicit | A06/A07_Triage_* з токеном |
| SC-05 | POST /api/auth/logout | Lab03Identity; auth-lab.js | завершення сеансу | так | так | explicit (до SignOutAsync) | A06_Logout_*; ручна перевірка |
| SC-06 | POST /api/auth/login | Lab03Identity; auth-lab.js | створення сеансу | ні | так | не застосовується: residual login-CSRF | — |
| SC-07 | POST /api/auth/register | Lab03Identity; auth-lab.js | створення акаунта | ні | так | не застосовується: residual | — |

## 9. Dependency and secret audit
Залежності: `dotnet restore` без NU1901–NU1904; `dotnet package list --vulnerable --include-transitive`, SDK 10.0.402, 12.11.2026 22:53, код 0: SecureLab.Api і SecureLab.Api.Tests — no vulnerable packages given the current sources (api.nuget.org). Advisories немає, рішень update/mitigate/acceptance і придушень немає. Межа: лише відомі на дату advisories цих джерел; досяжність і невідомі вразливості не оцінювалися.

Секрети: `git --no-pager grep -n -I -i -E 'password|passwd|secret|api.?key' -- .` — 101 збіг на старті, 113 після ЛР 6 (12 нових класифіковано: документація й StudyPassword зі змінної середовища). Accepted, study-only: infra/compose.yaml:9, appsettings.Development.json:3, SecureLabDesignTimeDbContextFactory.cs:10 (local-study-password лише для БД на 127.0.0.1). Пошук PEM private key / AKIA / ghp_ — 0. .env.example — лише POSTGRES_PORT; .gitignore ігнорує infra/.env і appsettings.Local.json. Для реального витоку видалення з файла недостатньо — потрібна rotation.

Журнали й аудит: SecureLab.AuthorizationAudit — authorization.denied (alice triage → 403, статус New) і authorization.allowed (morgan triage → 200, Triaged) з subject, action, resource, result, time, trace; SecureLab.RateLimit — path і trace без q; 500 — TraceId у журналі збігається з traceId відповіді.

## 10. Residual risks
| Ризик | Стан | Відповідальний / наступна дія |
|---|---|---|
| Транспорт: лише локальний HTTP, TLS/HSTS не перевірено | не перевірено | автор; перевірити на реальному deployment |
| Login-CSRF / register від імені жертви | прийнято: SameSite=Lax, JSON content type, login limiter | автор; розглянути анонімний bootstrap токена |
| In-memory rate limiter, спільний IP для login | прийнято для одного instance | автор; спільне сховище при масштабуванні |
| Історія Git, stash, клони не перевірені | не перевірено | автор; за підозри витоку |

## 11. Conclusion
Antiforgery охоплює всі cookie-автентифіковані mutation, дві знахідки виправлено з retest і positive regression, regression pack рівня «Добре» проходить повністю (36/36 автоматичних тестів і ручні процедури XSS/CORS/rate limit).

## 12. Evidence appendix
Відтворення: reset → вхід alice/bob/morgan → команди з карток F-01, F-02 і процедур звіту. Зв’язок відповіді з журналом: traceId 00-4568fefb…-e510cc04…-00 у 500 відповідає TraceId 4568fefb… у ExceptionHandlerMiddleware. Без паролів, cookie, токенів і connection strings.

## Декларація й журнал ШІ
Використовував. Claude (Anthropic) — покрокові команди, чернетки коду й тексту звіту.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| 12–13.11.2026 | Claude | AntiforgeryFilter, csrf.js, тести REG-CSRF-01, S-02, REG-SEARCH-01, rate limit search, виправлення F-01/F-02, текст review | вставлено у власний код, виправлено помилки збірки й зсуви дужок, підібрано дані seed | кожну зміну перевірено `dotnet test` (36/36), браузером і curl; ручні retest F-01, F-02 |
