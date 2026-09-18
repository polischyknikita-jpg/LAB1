# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

|Компонент|Розташування|Відповідальність|
|-|-|-|
|Browser client|`src/SecureLab.Api/Client/`|Надсилає HTTP-запити, безпечно показує відповідь через DOM API|
|Presentation|`Presentation/`|Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь|
|Application|`Application/`|Виконує сценарій отримання списку або деталей інциденту|
|Data|`Data/`|Відображає C#-сутності на PostgreSQL через EF Core/Npgsql|
|PostgreSQL|`infra/compose.yaml`|Зберігає навчальні дані у локальному контейнері|

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents або GET /api/incidents/{id}
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs
  → PostgreSQL
  → response DTO у Presentation/Contracts/
  → JSON
  → textContent/createTextNode у Client/app.js


```

Наскрізний маршрут для severity-summary (реалізовано в ЛР1):



клік на кнопку "Показати підсумок" у Client/index.html

&#x20; → handler loadSeveritySummary у Client/app.js

&#x20; → GET /api/incidents/severity-summary?status={опційно}

&#x20; → IncidentEndpoints.GetSeveritySummaryAsync (валідація status через allowlist)

&#x20; → IncidentQueries.GetSeveritySummaryAsync (GroupBy, доповнення нулями, сортування за критичністю)

&#x20; → SecureLabDbContext.Incidents / таблиця incidents

&#x20; → IncidentSeveritySummaryResponse\[] як JSON

&#x20; → renderSeveritySummary у Client/app.js

&#x20; → textContent у списку підсумку





## Межі довіри

Доповніть таблицю щонайменше трьома конкретними спостереженнями.

|Межа|Чому даним ще не можна довіряти|Де перевіряємо або обмежуємо|
|-|-|-|
|Користувач → Browser client|Користувач контролює введення|required на формі — лише зручність інтерфейсу, не захист; сервер перевіряє незалежно|
|Browser client → API|Клієнт і HTTP-запит можна змінити поза UI|Маршрутне обмеження :guid; allowlist-валідація status через Enum.TryParse + Enum.IsDefined → 400 Validation Problem|
|PostgreSQL → API → DOM|У БД може зберігатися раніше введений недовірений текст|Явна проєкція в response DTO (без прямого entity); textContent/createTextNode замість innerHTML|

## Конфігураційні входи

* `global.json` — версія .NET SDK;
* `src/SecureLab.Api/appsettings\*.json` — режим міграцій і локальний connection string;
* `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
* змінна середовища `ConnectionStrings\_\_SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.

