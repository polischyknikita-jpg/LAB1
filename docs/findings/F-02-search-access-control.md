# F-02. Пошук обходить правила доступу до інцидентів

**Статус:** Fixed  
**Актив:** конфіденційність інцидентів інших користувачів (назви й описи)  
**Компонент:** src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs, GET /api/incidents/search  
**Пріоритет:** P1

## Передумови і межі огляду

Commit 1bb17d2, гілка lab/6-hardening-review, профіль Development. `dotnet run --project src/SecureLab.Api -- --reset-database`. Акаунти seed: alice (Reporter), bob (Reporter), morgan (Analyst); пароль зі змінної SeedUsers__Password. Інциденти bob: 20000000-…-0002, 20000000-…-0004. Виключено: інші маршрути читання (покриті тестами ЛР 4).

## Відтворення

1. Без входу: `$r = Invoke-RestMethod "http://localhost:5080/api/incidents/search?q="; $r.Count`
2. Expected: 401. Actual: 200 і всі 5 інцидентів з назвами, включно з …0002 і …0004 bob.
3. Як alice у Console: `/api/incidents/` → 3 власні (…0005, …0003, …0001); `/api/incidents/search?q=` → 5, включно з чужими …0004 і …0002.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Будь-хто, навіть без входу, читає назви й описи всіх інцидентів інших користувачів (horizontal access / IDOR через пошук). Likelihood висока: маршрут публічний, достатньо одного GET без передумов.

## Першопричина

Маршрут пошуку з ЛР 2 зареєстровано окремо від групи /api/incidents без RequireAuthorization, а запит до БД не обмежує записи власником. Матриця доступу ЛР 4 застосована до групи й списку, але на пошук не поширилася.

## Виправлення

Пошук вимагає ролі Reporter або Analyst (`RequireAuthorization(policy => policy.RequireRole(...))`); для не-Analyst додано умову `OwnerUserId == userId`, де userId лише з verified principal. Rate limit «search» збережено. Commit: «lab6: F-02 search follows LR4 access matrix».

## Retest

Анонімний `GET /api/incidents/search?q=` → 401 Problem Details без даних. Alice: пошук повертає 3 власні інциденти, без …0004 і …0002. Автоматично: REG-SEARCH-01 `SearchAuthorizationTests.RegSearch01_RequiresLogin_ReporterSeesOnlyOwn_AnalystSeesAll`.

## Positive regression

Morgan (Analyst) бачить усі 5 інцидентів; `SearchMechanicsTests.Search_ReturnsJson` (alice) → 200 JSON; S-02 і SearchRateLimitTests проходять; `dotnet test SecureLab.sln -c Release` → 36/36.

## Залишковий ризик

Administrator отримує 403 на пошук так само, як на список (рішення матриці ЛР 4). Пошук за описом повертає опис повністю, але лише з доступних записів.

## Доказ

Звіт ЛР 6: рис. 76–77 (до), рис. 80–83 (після). Без password, cookie, token, secret.
