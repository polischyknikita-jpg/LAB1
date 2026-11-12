# F-01. Заголовки безпеки зникають на відповіді 500

**Статус:** Fixed  
**Актив:** захист браузера від MIME sniffing, витоку Referer і вбудовування сторінок у чужі фрейми  
**Компонент:** src/SecureLab.Api/Program.cs, middleware заголовків і UseExceptionHandler  
**Пріоритет:** P3

## Передумови і межі огляду

Commit review-start b7ace14 (тег v0.5.0), гілка lab/6-hardening-review. Локальний стенд Windows, PowerShell, curl.exe. API у Production без launch profile; ConnectionStrings__SecureLab вказує на недосяжний локальний порт 54399 (..\lr06-resources\commands\Production.ps1 -Mode broken). Акаунт не потрібен: запит анонімний. Виключено: реальний production host, reverse proxy.

## Відтворення

1. `powershell -NoProfile -ExecutionPolicy Bypass -File ..\lr06-resources\commands\Production.ps1 -Mode broken`
2. `curl.exe -sS -i -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" -H "Accept: application/problem+json" -d '{\"userName\":\"alice\",\"password\":\"NotARealPassword1!\"}'`
3. Expected: 500 Problem Details з тими самими X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, що й на 200/404.
4. Actual (до виправлення): 500 Problem Details без усіх трьох заголовків; на 200 і 404 вони присутні.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Відповідь 500 містить лише JSON Problem Details, тому прямої експлуатації немає: це неповне покриття браузерного control на одному класі відповідей. Impact низький, likelihood залежить від можливості спричинити необроблений виняток. Ризик у тому, що control, який вважається глобальним, тихо не діє на error path.

## Першопричина

Middleware заголовків стояв після `app.UseExceptionHandler()` і записував заголовки на початку запиту. ExceptionHandlerMiddleware при винятку очищує response (разом із заголовками) і формує нову 500.

## Виправлення

Middleware заголовків перенесено перед `UseExceptionHandler()`, заголовки встановлюються в `context.Response.OnStarting(...)`, тож додаються до будь-якої відповіді, включно з 500 від exception handler. `Append` для Referrer-Policy замінено присвоєнням (без дублювання). Commit: «lab6: F-01 security headers on error path».

## Retest

Повторено кроки 1–2 після виправлення: 500 Problem Details (лише title і traceId) містить `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`.

## Positive regression

Production `-Mode normal`: `GET /` → 200 і `GET /openapi/v1.json` → 404 мають ті самі три заголовки, кожен один раз. `dotnet test SecureLab.sln -c Release` → 35/35.

## Залишковий ризик

Заголовки, які могла б додати reverse proxy в реальному deployment, не перевірялися. Відповіді, що формуються до цього middleware (наприклад, помилки самого Kestrel), не покриваються.

## Доказ

Звіт ЛР 6: рис. 13 (до), рис. 72 (retest), рис. 73 (positive regression); traceId відповіді 500 зіставлено з журналом на етапі 1, п. 5. Без password, cookie, token, secret.
