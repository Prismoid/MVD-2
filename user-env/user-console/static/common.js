function nav(active) {
  document.write(`
    <header class="app-header">
      <div class="header-inner">
        <div class="header-title">
          <h1>MVD Console</h1>
          <p>Connector 経由で PKR / FC / AuthZ / Invoke を操作します。秘密鍵は Console DB に保存し、署名は Python FastAPI 側で生成します。</p>
        </div>
        <div class="header-badge">Local Console</div>
      </div>
    </header>
    <nav class="tabs">
      <a class="${active === 'pkr' ? 'active' : ''}" href="/pkr">Public Key Registry</a>
      <a class="${active === 'fc' ? 'active' : ''}" href="/fc">Federated Catalog</a>
      <a class="${active === 'authz' ? 'active' : ''}" href="/authz">Authorization</a>
      <a class="${active === 'invoke' ? 'active' : ''}" href="/invoke">Invoke Resource</a>
    </nav>
  `);
}

function showResult(data) {
  const el = document.getElementById('result');
  if (!el) return;
  el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw data;
  return data;
}

function val(id) { return document.getElementById(id).value.trim(); }

function esc(v) {
  return String(v ?? '').replace(/[&<>'"]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[c]));
}

async function loadLocalKeys(selectId) {
  const keys = await api('/api/local-keys');
  if (selectId) {
    const sel = document.getElementById(selectId);
    sel.innerHTML = keys.map(k => `<option value="${esc(k.user_id)}">${esc(k.user_id)}</option>`).join('');
  }
  return keys;
}

function createPager({ rows, tbodyId, searchId, pagerId, columns, pageSize = 10 }) {
  let page = 1;
  const tbody = document.getElementById(tbodyId);
  const search = document.getElementById(searchId);
  const pager = document.getElementById(pagerId);

  if (!tbody || !pager) return;

  if (search) {
    const clonedSearch = search.cloneNode(true);
    search.parentNode.replaceChild(clonedSearch, search);
    clonedSearch.addEventListener('input', () => { page = 1; render(); });
  }

  function currentSearchValue() {
    return (document.getElementById(searchId)?.value || '').toLowerCase();
  }

  function filteredRows() {
    const q = currentSearchValue();
    if (!q) return rows;
    return rows.filter(r => JSON.stringify(r).toLowerCase().includes(q));
  }

  function render() {
    const filtered = filteredRows();
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
    page = Math.min(Math.max(page, 1), pages);
    const start = (page - 1) * pageSize;
    const current = filtered.slice(start, start + pageSize);

    tbody.innerHTML = current.map(row =>
      `<tr>${columns.map(col => `<td>${col.render ? col.render(row) : esc(row[col.key])}</td>`).join('')}</tr>`
    ).join('');

    pager.innerHTML = `
      <button class="secondary small" ${page <= 1 ? 'disabled' : ''} data-page="prev">Prev</button>
      <span>${page} / ${pages} (${filtered.length} items)</span>
      <button class="secondary small" ${page >= pages ? 'disabled' : ''} data-page="next">Next</button>
    `;

    pager.querySelector('[data-page="prev"]')?.addEventListener('click', () => { page--; render(); });
    pager.querySelector('[data-page="next"]')?.addEventListener('click', () => { page++; render(); });
  }

  render();
}
