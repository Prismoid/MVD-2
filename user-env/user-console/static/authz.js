async function loadGranteeCandidates() {
  const keys = await loadLocalKeys('authz-user');
  const datalist = document.getElementById('grantee-candidates');
  if (!datalist) return;
  datalist.innerHTML = keys.map(k => `<option value="${esc(k.user_id)}"></option>`).join('');
}

async function loadAuthz() {
  try {
    await loadGranteeCandidates();
    const rows = await api('/api/authz/debug/show_all');
    document.getElementById('authz-body').innerHTML = rows.map(x =>
      `<tr><td>${esc(x.resource_id || '')}</td><td>${esc(x.access_grantee_id || '')}</td><td>${esc(x.expired_at || '')}</td></tr>`
    ).join('');
  } catch (e) { showResult(e); }
}

function authzPayload() {
  return {
    user_id: val('authz-user'),
    resource_id: val('resource-id'),
    access_grantee_id: val('grantee-id'),
    expired_at: val('expired-at'),
  };
}

async function addAuthz() {
  try {
    showResult(await api('/api/console/authz/add', {
      method: 'POST',
      body: JSON.stringify(authzPayload()),
    }));
    await loadAuthz();
  } catch (e) { showResult(e); }
}

async function updateAuthz() {
  try {
    showResult(await api('/api/console/authz/update', {
      method: 'POST',
      body: JSON.stringify(authzPayload()),
    }));
    await loadAuthz();
  } catch (e) { showResult(e); }
}

async function deleteAuthz() {
  try {
    showResult(await api('/api/console/authz/delete', {
      method: 'POST',
      body: JSON.stringify({
        user_id: val('authz-user'),
        resource_id: val('resource-id'),
        access_grantee_id: val('grantee-id'),
      }),
    }));
    await loadAuthz();
  } catch (e) { showResult(e); }
}

async function deleteAllAuthz() {
  if (!confirm('Debug: Authorization DB の全エントリを削除します。実行しますか？')) return;
  try {
    showResult(await api('/api/console/authz/debug/delete-all', { method: 'POST' }));
    await loadAuthz();
  } catch (e) { showResult(e); }
}

loadAuthz();
