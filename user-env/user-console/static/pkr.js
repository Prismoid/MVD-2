async function loadPkr() {
  try {
    await loadLocalKeys('pkr-user');
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

async function loadLocalKeysForTable() {
  const rows = await loadLocalKeys('pkr-user');
  createPager({
    rows,
    tbodyId: 'local-key-body',
    searchId: 'local-key-search',
    pagerId: 'local-key-pager',
    columns: [
      { key: 'user_id' },
      { render: row => `<pre class="inline-key">${esc(row.private_key || '')}</pre>` },
      { key: 'registered_at' },
    ],
  });
}

async function loadPkrDb() {
  // Public Key Registry 全体ではなく、この Console の Local Keys と user_id / public_key が一致する行のみ表示する。
  const rows = await api('/api/console/pkr/local-registered');
  createPager({
    rows,
    tbodyId: 'pkr-body',
    searchId: 'pkr-search',
    pagerId: 'pkr-pager',
    columns: [
      { key: 'user_id' },
      { render: row => `<pre class="inline-key">${esc(row.public_key || '')}</pre>` },
      { key: 'registered_at' },
    ],
  });
}

async function createLocalKey() {
  try {
    showResult(await api('/api/local-keys', {
      method: 'POST',
      body: JSON.stringify({ user_id: val('new-user-id') }),
    }));
    await loadLocalKeysForTable();
    await loadLocalKeys('pkr-user');
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

async function registerPkr() {
  try {
    showResult(await api('/api/console/pkr/register', {
      method: 'POST',
      body: JSON.stringify({ user_id: val('pkr-user') }),
    }));
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

async function updatePkr() {
  try {
    showResult(await api('/api/console/pkr/update', {
      method: 'POST',
      body: JSON.stringify({ user_id: val('pkr-user') }),
    }));
    await loadLocalKeysForTable();
    await loadLocalKeys('pkr-user');
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

async function deletePkr() {
  try {
    showResult(await api('/api/console/pkr/delete', {
      method: 'POST',
      body: JSON.stringify({ user_id: val('pkr-user') }),
    }));
    await loadLocalKeysForTable();
    await loadLocalKeys('pkr-user');
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

async function deleteAllLocalKeys() {
  if (!confirm('Debug: Local Keys を全て削除します。PKR DB 側の公開鍵は削除されません。実行しますか？')) return;
  try {
    showResult(await api('/api/local-keys/debug/delete-all', { method: 'POST' }));
    await loadLocalKeysForTable();
    await loadLocalKeys('pkr-user');
    await loadPkrDb();
  } catch (e) { showResult(e); }
}

loadLocalKeysForTable().then(loadPkrDb).catch(showResult);
