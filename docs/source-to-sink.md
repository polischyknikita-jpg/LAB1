# \# Власна карта source-to-sink

# 

# Поле: Incident.Description. Стан: vulnerable commit e98b2a0 (scaffold lab-05-start-v1 поверх v0.4.0). Сторінка: http://localhost:5080/browser-lab.html. Вхід: Alice (Reporter) створює запис, Morgan (Analyst) переглядає. Guid запису з marker: заповнюється в Етапі 2.

# 

# \## Потік 1 — Incident.Description

# 

# | Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |

# |---|---|---|---|

# | Source | Client/browser-lab.html, форма `#edit`, `<textarea name="description">` | текст, уведений користувачем | Elements; контрольоване користувачем |

# | Request | Client/browser-lab.js, обробник `submit` форми `#edit` → `fetch("/api/incidents", { method: "POST" })` | JSON-поле `description` (разом із `title`, `severity: "Low"`, `occurredAtUtc`) | Network → Payload; контрольоване користувачем |

# | Validation/mapping | Scaffolding/Lab02Endpoints.cs, `MapPost("/api/incidents")`, `CreateIncidentRequest.Description` | обов'язковість, довжина ≤ 4000, `Trim()`; HTML-очищення немає | валідація перевіряє бізнес-формат, а не безпечність для HTML; значення лишається недовіреним |

# | Storage | Data/Entities/Incident.cs, `Incident.Description`; PostgreSQL, колонка description | те саме значення після `Trim()` | збережене значення користувача; запис у БД не робить його довіреним |

# | Response | Presentation/Endpoints/IncidentEndpoints.cs, `GetDetailsAsync` (перевірка Read) → Application/Incidents/IncidentQueries.cs, `GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON-поле `description` у відповіді `GET /api/incidents/{id}` | Network → Response; JSON-екранування лапок не є захистом HTML sink; недовірене для браузера |

# | Client transform | Client/browser-lab.js, функція `load()`: `current = await response.json()` | `current.description` без перетворень | значення передається далі як є |

# | Sink/context | Client/browser-lab.js, `load()`: `document.querySelector("#description").innerHTML = current.description` | елемент `<div id="description">` | \*\*HTML context, небезпечно\*\*: рядок розбирає HTML parser, атрибути `on\*` виконуються як JavaScript |

# 

# \## Інвентаризація DOM-операцій у browser-lab.js

# 

# | Місце (`load()` / submit) | Дані | Категорія даних | Контекст | Рішення |

# |---|---|---|---|---|

# | `#status.textContent = \\`GET: ${response.status}\\`` | HTTP-статус | server-generated | текстовий вузол | безпечно |

# | `#title.textContent = current.title` | назва інциденту | збережене значення користувача | текстовий вузол | безпечно |

# | `#description.innerHTML = current.description` | опис | збережене значення користувача | \*\*HTML parser\*\* | \*\*небезпечно → замінити safe DOM API\*\* |

# | `#comments.replaceChildren()` | — | — | очищення контейнера | безпечно |

# | `paragraph.innerHTML = comment.text` (цикл `comments`) | текст коментаря | збережене значення користувача | \*\*HTML parser\*\* | \*\*небезпечно → замінити safe DOM API\*\* |

# | `form.elements.description.value = current.description` | опис у полі форми | збережене значення користувача | властивість `value` поля форми (текст) | безпечно |

# | `#incident-id.value = created.id` | Guid створеного запису | server-generated | властивість `value` | безпечно |

# | browser-lab.html: статична розмітка, `<script src="browser-lab.js">` | — | trusted constant | статичний HTML | безпечно |

# 

# Динамічних `href`/`src`, inline event handlers, `eval` чи `new Function` у власному клієнті немає. Для порівняння: штатний Client/app.js відображає ті самі поля через `createTextElement` (`textContent`) і `createTextNode` — безпечно.

# 

# Для «Добре»: потік 2 IncidentComment.Text додається в Етапі 2.

