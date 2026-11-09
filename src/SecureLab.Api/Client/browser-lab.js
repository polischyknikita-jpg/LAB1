let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");

// ЛР 05: єдиний безпечний helper для звичайного тексту.
// Структуру задає код; значення потрапляє лише в текстовий вузол і не розбирається як HTML.
function renderPlainText(element, text) {
    element.replaceChildren(document.createTextNode(text ?? ""));
    return element;
}

async function load() {
    const response = await fetch(`/api/incidents/${id()}`);
    status.textContent = `GET: ${response.status}`;
    if (!response.ok) return;
    current = await response.json();
    renderPlainText(document.querySelector("#title"), current.title);
    renderPlainText(document.querySelector("#description"), current.description);
    const comments = document.createDocumentFragment();
    for (const comment of current.comments ?? []) {
        comments.append(renderPlainText(document.createElement("p"), comment.text));
    }
    document.querySelector("#comments").replaceChildren(comments);
    document.querySelector("#edit").elements.description.value = current.description;
}
document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
    event.preventDefault();
    const response = await fetch("/api/incidents", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            title: event.currentTarget.elements.title.value, description: event.currentTarget.elements.description.value,
            severity: "Low", occurredAtUtc: new Date().toISOString()
        })
    });
    status.textContent = `POST: ${response.status}`;
    if (response.ok) {
        const created = await response.json();
        document.querySelector("#incident-id").value = created.id;
        await load();
    }
});