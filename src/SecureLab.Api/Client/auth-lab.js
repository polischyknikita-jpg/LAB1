// ЛР 03, добрий рівень: браузерний сценарій register → login → profile → create → logout.
// Правила: cookie надсилає сам браузер (HttpOnly); credentials і principal не зберігаються
// у localStorage/sessionStorage/DOM dataset/Console; дані показуються лише через textContent.

const stateLabel = document.querySelector("#state");
const result = document.querySelector("#result");
const registerResult = document.querySelector("#register-result");
const createResult = document.querySelector("#create-result");
const profile = document.querySelector("#profile");

// Запити лише на свій origin; cookie додається браузером автоматично.
async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

function postJson(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

function isJson(response) {
  return (response.headers.get("Content-Type") ?? "").includes("json");
}

function showState(state) {
  const labels = {
    "signed-in": "Сеанс активний",
    "anonymous": "Не ввійшли",
    "unknown": "Невідомо (помилка перевірки)"
  };
  stateLabel.textContent = labels[state];
}

function clearProfile() {
  profile.replaceChildren();
}

function showProfile(data) {
  clearProfile();
  // Лише дозволені поля DTO /api/me.
  const fields = [["Id", data.id], ["Ім’я користувача", data.userName],
    ["Відображуване ім’я", data.displayName], ["Роль", data.role]];
  for (const [label, value] of fields) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value ?? "";
    profile.append(dt, dd);
  }
}

// Коротке безпечне повідомлення про відмову: status, title і назви полів з помилками.
async function describeFailure(response) {
  if (!isJson(response)) {
    return `${response.status}`;
  }
  const problem = await response.json();
  const fields = problem.errors ? Object.keys(problem.errors).join(", ") : "";
  return `${response.status} ${problem.title ?? ""}${fields ? " — поля: " + fields : ""}`;
}

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    if (response.status === 204) {
      showState("signed-in");
    } else if (response.status === 401) {
      showState("anonymous");
      clearProfile();
    } else {
      showState("unknown");
    }
  } catch {
    showState("unknown");
  }
}

async function loadProfile() {
  const response = await apiFetch("/api/me");
  if (response.ok && isJson(response)) {
    showProfile(await response.json());
    return response.status;
  }
  clearProfile();
  if (response.status === 401) {
    showState("anonymous");
  }
  return response.status;
}

// 1. Реєстрація: 201 без автоматичного входу; пароль очищується після спроби.
document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  try {
    const response = await postJson("/api/auth/register", {
      userName: data.userName, email: data.email,
      displayName: data.displayName, password: data.password
    });
    if (response.status === 201) {
      const created = await response.json();
      registerResult.textContent = `Register: 201 — створено ${created.userName}. Тепер увійдіть.`;
    } else {
      registerResult.textContent = `Register: ${await describeFailure(response)}`;
    }
  } catch {
    registerResult.textContent = "Register: помилка мережі";
  }
});

// 2. Вхід → стан і профіль.
document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  const response = await postJson("/api/auth/login", { userName: data.userName, password: data.password });
  result.textContent = `Login: ${response.status}`;
  await refreshSessionState();
  if (response.status === 204) {
    const status = await loadProfile();
    result.textContent += ` · /api/me: ${status}`;
  }
});

document.querySelector("#me").addEventListener("click", async () => {
  const status = await loadProfile();
  result.textContent = `/api/me: ${status}`;
});

// 3. Створення інциденту: власника в JSON немає, його визначає сервер.
document.querySelector("#create").addEventListener("submit", async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  const occurred = new Date(data.occurredAt);
  if (Number.isNaN(occurred.getTime())) {
    createResult.textContent = "Вкажіть час інциденту.";
    return;
  }
  const response = await postJson("/api/incidents", {
    title: data.title,
    description: data.description,
    severity: data.severity,
    occurredAtUtc: occurred.toISOString()
  });
  if (response.status === 201) {
    const created = await response.json();
    createResult.textContent = `Create: 201 — «${created.title}», id ${created.id}`;
  } else {
    createResult.textContent = `Create: ${await describeFailure(response)}`;
    if (response.status === 401) {
      showState("anonymous");
      clearProfile();
    }
  }
});

// 4. Вихід: серверний sign-out, очищення UI і повторна перевірка /api/me.
document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  result.textContent = `Logout: ${response.status}`;
  clearProfile();
  createResult.textContent = "";
  registerResult.textContent = "";
  const check = await apiFetch("/api/me");
  result.textContent += ` · повторний /api/me: ${check.status}`;
  await refreshSessionState();
});

refreshSessionState();
