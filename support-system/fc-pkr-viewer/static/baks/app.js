const PAGE_SIZE = 10;

const state = {
  fcItems: [],
  fcPage: 1,
  pkrItems: [],
  pkrPage: 1,
};

function escapeHtml(value) {
  if (value === null || value === undefined) return "";

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function asArray(data) {
  if (data === null || data === undefined) return [];
  return Array.isArray(data) ? data : [data];
}

function pageCount(items) {
  return Math.max(1, Math.ceil(items.length / PAGE_SIZE));
}

function pageItems(items, page) {
  const start = (page - 1) * PAGE_SIZE;
  return items.slice(start, start + PAGE_SIZE);
}

function clampPage(page, items) {
  return Math.min(Math.max(1, page), pageCount(items));
}

function renderPager(pagerId, items, page, setPageFunctionName) {
  const pager = document.getElementById(pagerId);
  if (!pager) return;

  if (items.length === 0) {
    pager.innerHTML = "";
    return;
  }

  const totalPages = pageCount(items);
  const itemLabel = items.length === 1 ? "item" : "items";

  pager.innerHTML = `
    <button class="pager-button" onclick="${setPageFunctionName}(${page - 1})" ${page === 1 ? "disabled" : ""}>Prev</button>
    <span class="pager-status">${page} / ${totalPages} (${items.length} ${itemLabel})</span>
    <button class="pager-button" onclick="${setPageFunctionName}(${page + 1})" ${page === totalPages ? "disabled" : ""}>Next</button>
  `;
}

async function requestJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();

  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_) {
      data = text;
    }
  }

  if (!res.ok) {
    const message = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    throw new Error(message || `Request failed: ${res.status}`);
  }

  return data;
}

function showError(summaryId, error) {
  const message = error instanceof Error ? error.message : String(error);
  document.getElementById(summaryId).textContent = `Error: ${message}`;
}

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach(el => {
    el.classList.remove("active");
  });

  document.querySelectorAll(".panel").forEach(el => {
    el.classList.remove("active");
  });

  if (tab === "fc") {
    document.querySelectorAll(".tab")[0].classList.add("active");
    document.getElementById("fc-panel").classList.add("active");
    loadFederatedCatalog();
  } else {
    document.querySelectorAll(".tab")[1].classList.add("active");
    document.getElementById("pkr-panel").classList.add("active");
  }
}

function buildQuery(params) {
  const q = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value && value.trim() !== "") {
      q.append(key, value.trim());
    }
  });

  const s = q.toString();
  return s ? `?${s}` : "";
}

function renderFederatedCatalog() {
  const items = state.fcItems;
  const tbody = document.getElementById("fc-body");
  state.fcPage = clampPage(state.fcPage, items);

  document.getElementById("fc-summary").textContent =
    `${items.length} catalog entries`;

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No catalog entries found.</td></tr>`;
    renderPager("fc-pager", items, state.fcPage, "setFcPage");
    return;
  }

  tbody.innerHTML = pageItems(items, state.fcPage).map(item => `
    <tr>
      <td><span class="pill">${escapeHtml(item.resource_id)}</span></td>
      <td class="mono">${escapeHtml(item.user_id)}</td>
      <td>${escapeHtml(item.description)}</td>
      <td class="mono">${escapeHtml(item.endpoint)}</td>
      <td class="mono">${escapeHtml(item.resource_path)}</td>
      <td class="mono">${escapeHtml(item.registered_at)}</td>
    </tr>
  `).join("");

  renderPager("fc-pager", items, state.fcPage, "setFcPage");
}

function setFcPage(page) {
  state.fcPage = page;
  renderFederatedCatalog();
}

async function loadFederatedCatalog() {
  const resourceId = document.getElementById("fc-resource-id").value;
  const userId = document.getElementById("fc-user-id").value;
  const keyword = document.getElementById("fc-keyword").value;

  const query = buildQuery({
    resource_id: resourceId,
    user_id: userId,
    keyword: keyword,
  });

  try {
    const data = await requestJson(`/api/fc${query}`);
    state.fcItems = asArray(data);
    state.fcPage = 1;
    renderFederatedCatalog();
  } catch (error) {
    state.fcItems = [];
    state.fcPage = 1;
    renderFederatedCatalog();
    showError("fc-summary", error);
  }
}

function renderPublicKeys() {
  const items = state.pkrItems;
  const tbody = document.getElementById("pkr-body");
  state.pkrPage = clampPage(state.pkrPage, items);

  document.getElementById("pkr-summary").textContent =
    `${items.length} public key ${items.length === 1 ? "entry" : "entries"}`;

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No public keys found.</td></tr>`;
    renderPager("pkr-pager", items, state.pkrPage, "setPkrPage");
    return;
  }

  tbody.innerHTML = pageItems(items, state.pkrPage).map(item => `
    <tr>
      <td><span class="pill">${escapeHtml(item.user_id)}</span></td>
      <td class="mono">
        <div class="key-box">${escapeHtml(item.public_key)}</div>
      </td>
      <td class="mono">${escapeHtml(item.registered_at)}</td>
    </tr>
  `).join("");

  renderPager("pkr-pager", items, state.pkrPage, "setPkrPage");
}

function setPkrPage(page) {
  state.pkrPage = page;
  renderPublicKeys();
}

async function loadPublicKey() {
  const userId = document.getElementById("pkr-user-id").value.trim();
  const tbody = document.getElementById("pkr-body");

  if (!userId) {
    state.pkrItems = [];
    state.pkrPage = 1;
    document.getElementById("pkr-summary").textContent = "Enter user_id.";
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No user_id specified.</td></tr>`;
    renderPager("pkr-pager", state.pkrItems, state.pkrPage, "setPkrPage");
    return;
  }

  let item = null;
  try {
    item = await requestJson(`/api/pkr/${encodeURIComponent(userId)}`);
  } catch (error) {
    state.pkrItems = [];
    state.pkrPage = 1;
    renderPublicKeys();
    showError("pkr-summary", error);
    return;
  }

  state.pkrItems = item ? [item] : [];
  state.pkrPage = 1;

  if (!item) {
    document.getElementById("pkr-summary").textContent = "0 public key entries";
    tbody.innerHTML = `<tr><td colspan="3" class="empty">Public key not found.</td></tr>`;
    renderPager("pkr-pager", state.pkrItems, state.pkrPage, "setPkrPage");
    return;
  }

  renderPublicKeys();
}

async function loadAllPublicKeys() {
  try {
    const items = await requestJson("/api/pkr");
    state.pkrItems = asArray(items);
    state.pkrPage = 1;
    renderPublicKeys();
  } catch (error) {
    state.pkrItems = [];
    state.pkrPage = 1;
    renderPublicKeys();
    showError("pkr-summary", error);
  }
}

async function deleteAllFederatedCatalog() {
  if (!confirm("Delete all Federated Catalog entries?")) return;

  try {
    await requestJson("/api/fc/debug/delete-all", { method: "DELETE" });
    state.fcItems = [];
    state.fcPage = 1;
    renderFederatedCatalog();
    document.getElementById("fc-summary").textContent = "All Federated Catalog entries deleted.";
  } catch (error) {
    showError("fc-summary", error);
  }
}

async function deleteAllPublicKeys() {
  if (!confirm("Delete all Public Key Registry entries?")) return;

  try {
    await requestJson("/api/pkr/debug/delete-all", { method: "DELETE" });
    state.pkrItems = [];
    state.pkrPage = 1;
    renderPublicKeys();
    document.getElementById("pkr-summary").textContent = "All Public Key Registry entries deleted.";
  } catch (error) {
    showError("pkr-summary", error);
  }
}

loadFederatedCatalog();
