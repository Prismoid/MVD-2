function updateAuthFields() {
  const type = val('authType') || 'none';
  document.querySelectorAll('.auth-fields').forEach(el => { el.hidden = true; });

  const target = {
    basic: 'basicAuthFields',
    bearer: 'bearerAuthFields',
    custom: 'customAuthFields',
  }[type];

  if (target) {
    document.getElementById(target).hidden = false;
  }
}

async function init() {
  try {
    await loadLocalKeys('user-id');
    updateAuthFields();
    document.getElementById('authType').addEventListener('change', updateAuthFields);
  } catch(e) {
    showResult(e);
  }
}

async function invokeResource() {
  try {
    const data = await api('/api/console/invoke', {
      method: 'POST',
      body: JSON.stringify({
        resource_id: val('resource-id'),
        user_id: val('user-id'),
        method: val('method'),
        query_params: val('query-params'),
        body: document.getElementById('body').value,
        extra_headers: document.getElementById('extraHeaders').value,
        auth_type: val('authType'),
        basic_user: val('basicUser'),
        basic_pass: document.getElementById('basicPass').value,
        bearer_token: val('bearerToken'),
        custom_auth: val('customAuth'),
      }),
    });
    showResult(data);
  } catch(e) {
    showResult(e);
  }
}

init();
