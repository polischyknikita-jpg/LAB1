// ЛР 06: спільний helper для змінювальних запитів (same-origin).
// Request token береться з /api/antiforgery/token і тримається лише в пам'яті сторінки
// (не в localStorage, не в DOM, не в Console). Cookie-частину браузер надсилає сам.
const csrfHeaderName = "X-CSRF-TOKEN";
let csrfToken = null;

// Після login або logout старий token належить іншому principal — скидаємо його.
function resetCsrfToken() {
  csrfToken = null;
}

async function sendMutation(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  if (!csrfToken) {
    const tokenResponse = await fetch("/api/antiforgery/token", { credentials: "same-origin", cache: "no-store" });
    if (!tokenResponse.ok) {
      return tokenResponse; // напр. 401 без сеансу — UI покаже статус
    }
    csrfToken = (await tokenResponse.json()).token;
  }
  const headers = new Headers(options.headers ?? {});
  headers.set(csrfHeaderName, csrfToken);
  return fetch(url, { ...options, headers, credentials: "same-origin" });
}

function sendJsonMutation(path, body, method = "POST") {
  return sendMutation(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}
