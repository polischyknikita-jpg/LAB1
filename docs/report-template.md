# Звіт до лабораторної роботи № TODO

## 1\. Ідентифікація стану

\- Варіант: 2-A «Трекер інцидентів».

\- Гілка: `lab/1-system`.

\- Фінальний тег: `v0.1.0`.

\- Commit hash: .



2\. Змінений маршрут

Реалізовано endpoint GET /api/incidents/severity-summary — підрахунок кількості інцидентів за рівнем важливості (severity), з опційним фільтром за статусом.



Маршрут: клік на кнопку "Показати підсумок" (Client/index.html) → handler loadSeveritySummary (Client/app.js) → GET /api/incidents/severity-summary → IncidentEndpoints.GetSeveritySummaryAsync (валідація status через allowlist) → IncidentQueries.GetSeveritySummaryAsync (GroupBy за severity, доповнення нулями для відсутніх рівнів, сортування за критичністю: Critical→High→Medium→Low) → SecureLabDbContext.Incidents → PostgreSQL таблиця incidents → IncidentSeveritySummaryResponse\[] як JSON → renderSeveritySummary → textContent у списку.



Ключові файли: IncidentEndpoints.cs, IncidentQueries.cs, IncidentResponses.cs, app.js, index.html.



3\. Виконані зміни



1\. Додано record IncidentSeveritySummaryResponse(string Severity, int Count) у Presentation/Contracts/IncidentResponses.cs.

2\. Додано метод IncidentQueries.GetSeveritySummaryAsync — групування за Severity, AsNoTracking, доповнення відсутніх рівнів нулями, сортування Critical→High→Medium→Low.

3\. Замінено baseline-заглушку (501) на реальний endpoint у IncidentEndpoints.cs; додано метод GetSeveritySummaryAsync з валідацією query parameter status через Enum.TryParse + Enum.IsDefined (400 при некоректному значенні).

4\. Додано структуроване журналювання (LogInformation на початку і в кінці операції, з параметрами Status і GroupCount).

5\. Додано кнопку "Показати підсумок", статус-текст і список у index.html.

6\. Додано функції renderSeveritySummary і loadSeveritySummary у app.js з обробкою станів завантаження, порожнього результату та безпечної помилки.

7\. Оновлено tests/http/incidents.http — додано 4 нові сценарії (успішний, з фільтром, порожній результат, некоректний статус).



## 4\. Перевірка

|ID|Передумови|Дія|Очікувано|Фактично|Доказ|
|-|-|-|-|-|-|
|T-01<br />|PostgreSQL healthy, API запущено|GET /health|200, ready|200, {"status":"ready"}|скріншот|
|T-06|реалізований етап 3, seed відновлено|GET /api/incidents/severity-summary|200, Critical:0/High:1/Medium:1/Low:1|200, точно збіглось|скріншот curl|
|T-06b|-|GET .../severity-summary?status=Closed|200, усі нулі|200, усі count:0|скріншот curl|
|T-06c|-|GET .../severity-summary?status=Unknown|400 Validation Problem|400, правильне повідомлення||
|T-07|API+клієнт запущено|клік на кнопку підсумку|безпечний результат у DOM|список правильно показаний|скріншот браузера|

## 5\. Security-сценарій

Ця лабораторна робота не передбачає роботи з навмисно вразливим станом (SQLi, XSS тощо) — такі сценарії будуть у наступних лабораторних роботах курсу. У межах ЛР1 перевірено безпечні патерни (параметризовані запити через EF Core, явна проєкція DTO, безпечний вивід через textContent), описані в розділі меж довіри docs/architecture.md.



6\. Висновок

Реалізовано наскрізне розширення трекера інцидентів (підрахунок за severity) з дотриманням принципів безпеки: окремий response DTO без зайвих полів, валідація вхідних параметрів за allowlist, безпечне відображення даних у DOM. Усі 4 готові автоматизовані тести залишились зеленими після внесених змін. Функціонал перевірено щонайменше на 4 HTTP-сценаріях, включно з порожнім і некоректним випадками.

