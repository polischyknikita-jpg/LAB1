# Докази безпеки браузера (DEL-01)

Рівень: добрий («Добре»).

## Стенд і Git-стан (Для всіх)



Vulnerable commit: e98b2a0. Seed-коментар із marker (стан «до» для коментаря): окремий commit. Fixed commit (safe DOM): c9cd6c0. CORS policy: 8b97e19. CSP enforcement: 8d0b99e. v0.5.0 вказує на commit із документами доказів поверх 8d0b99e. Передавання: приватний remote origin (GitHub).



ОС: Windows 11. Браузер: Chrome. API origin: http://localhost:5080; навчальні probes: http://localhost:4173 (дозволений), http://localhost:4174 (контрольний недозволений).



Початковий тег v0.4.0 → 0538b43. Робоча гілка lab/5-browser-xss.

Release scaffold: lab-05-start-v1. base\_commit: 0538b438c6e506767888d5c8a4c0ea2ae76c0281. entry\_parent: 0538b438c6e506767888d5c8a4c0ea2ae76c0281 (збігається з base\_commit: commit політики SDK не знадобився).

Vulnerable commit: e98b2a0. Fixed commit: (заповнюється в Етапі 2). v0.5.0: (заповнюється в Етапі 4). Передавання: приватний remote origin.



Гіпотеза й REG-XSS-01 (Для всіх)

REG-XSS-01.

\- Передумови: commit із тегом v0.5.0; `docker compose … up -d --wait`; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`; Development, http://localhost:5080; користувачі alice (Reporter) і morgan (Analyst).

\- Вхід: рядок із resources/lab05-marker.txt без змін.

\- Кроки: /auth-lab.html → вхід alice → /browser-lab.html → Ctrl+Shift+R → команда перевірки (null) → назва «Marker N», опис = marker → «Створити й прочитати» → команда перевірки; те саме для seed-інциденту 20000000-0000-0000-0000-000000000001 (коментар …000000000005) і в сеансі morgan.

\- Очікуваний результат: marker видно як текст, у #description і #comments лише текстові вузли, команда перевірки повертає null; апостроф/лапки, 5 < 7, Unicode, <b>…</b>, seed …0003 і 3900 символів відображаються без змін.

\- Негативний контроль: на e98b2a0 marker виконувався (data-lab05-marker="executed") в сеансах Alice і Morgan.

\- Доказ: Network (Payload/Response без змін), Elements (текстовий вузол), Console (null); файли Client/browser-lab.js, Data/DbSeeder.cs.



Гіпотеза: значення з поля `<textarea name="description">` форми `#edit` на /browser-lab.html (JSON-поле `description` запиту POST /api/incidents) зберігається в Incident.Description у PostgreSQL, повертається через поле `description` відповіді GET /api/incidents/{id} (IncidentDetailsResponse.Description) і передається у `document.querySelector("#description").innerHTML` у функції `load()` файлу browser-lab.js як HTML context; тому за умови, що збережений текст містить HTML-розмітку з атрибутом обробника подій, браузер може інтерпретувати дані не як звичайний текст, а виконати JavaScript у сеансі будь-якого користувача, якому дозволено читати цей інцидент. Аналогічний sink для тексту коментарів: `paragraph.innerHTML = comment.text`.



Передумови: локальний стенд, API http://localhost:5080 (Development); користувачі Alice (Reporter, автор запису), Morgan (Analyst, привілейований глядач), Bob (Reporter, контроль); пароль задається змінною SeedUsers\_\_Password поза Git. Marker — єдиний рядок із resources/lab05-marker.txt. Команди: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`. Create/read: форма «Створити й прочитати» на /browser-lab.html (POST /api/incidents, потім GET /api/incidents/{id}). Guid запису з marker: заповнюється в Етапі 2.

|Спостереження|До fix|Після fix|Посилання на доказ|
|-|-|-|-|
|Значення в БД/API||||
|DOM основного Description||||
|Дія marker||||
|Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок|апостроф, лапки, 5 < 7 і 9 > 3, Київ — Ω — без змін, текстовий вузол; <b>жирний</b> текст → елемент <b>; seed …0003 → видно лише «Текст», решта в елементі <script>|||
|Довжина за власними правилами ЛР 2|3900 символів (межа 4000): POST 201, показано повністю, textContent.length = 3900|||
|Вікно Morgan: GET і перевірка marker; контроль Bob||||

Finding.

\- Актив: сеанс браузера користувача, який переглядає інцидент (зокрема Analyst Morgan), і дані, доступні від його імені.

\- Передумови: локальний обліковий запис Reporter (Alice) з правом створити інцидент; контроль над полем опису (або текстом коментаря через seed).

\- Першопричина: browser-lab.js, функція load(), передає збережені значення користувача current.description і comment.text у властивість innerHTML (HTML context), тому HTML parser створює елементи, а атрибути on\* виконуються як JavaScript.

\- Вплив на стенді: marker лише встановив data-lab05-marker="executed" на локальному #lab05-marker-target у сеансах Alice і Morgan.

\- Виправлення: safe DOM rendering — єдиний helper renderPlainText записує значення в текстовий вузол (document.createTextNode) для опису й кожного коментаря; formatted HTML за контрактом не дозволено, sanitizer не потрібен.

\- Retest: той самий marker відображається як текст, команда перевірки повертає null.

\- Залишковий ризик: інші клієнти/поля, які не досліджено; сторонні скрипти (розширення браузера, Scalar UI у Development).

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповніть до зміни policy:

|Сценарій|Чи доходить request до API?|Чи може JavaScript прочитати response?|Чому|
|-|-|-|-|
|same-origin 5080 → API||||
|simple GET 4173 → API||||
|simple GET 4174 → API||||
|curl/.http → API||не застосовується||
|preflighted 4173 → API («Добре / Відмінно»)||||

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

|Клієнт / простий запит|До policy|Fixed state|Status, ACAO, Console / доказ|
|-|-|-|-|
|Same-origin 5080||||
|Allowed 4173||||
|Disallowed 4174||||
|Direct HTTP / curl||||

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …



Директива CSP	Фактичні ресурси застосунку	Обране джерело / причина

default-src	HTML, JS (app.js, browser-lab.js, auth-lab.js), CSS (auth-lab.css та стилі /), fetch до /api/… — усе з http://localhost:5080	'self': зовнішніх ресурсів немає

script-src	лише власні .js з 'self', без inline-скриптів	через default-src 'self'; unsafe-inline не потрібен

style-src	власні CSS-файли; inline <style> з auth-lab.html перенесено в auth-lab.css	через default-src 'self'; unsafe-inline не потрібен

connect-src	fetch лише до того самого origin (/api/…, /health)	через default-src 'self'; probes 4173/4174 не додано, бо це тимчасовий стенд

img-src	власних зображень немає	через default-src 'self'; зовнішнє зображення заблоковано (рис. 74)

frame-ancestors	вбудовування сторінок не потрібне	'none' вказано явно, бо директива не має fallback до default-srcМісце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

|Header / control|Фактичне значення|Ризик і межа захисту / policy rationale|
|-|-|-|
|X-Content-Type-Options|nosniff|забороняє браузеру вгадувати тип вмісту за байтами; не замінює правильний Content-Type і валідацію|
|Referrer-Policy|no-referrer|не передає адресу сторінки в Referer; навігація клієнта не залежить від Referer, тому суворе значення підходить; не дозволяє зберігати secrets в URL|
|frame-ancestors|‘none’|забороняє вбудовування сторінок в <iframe> чужих сайтів, тобто зменшує ризик clickjacking; не замінює авторизацію та виправлення XSS|

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … safe-url.js / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавайте. Перед поданням повторіть чекліст для свого накопичувального рівня.

