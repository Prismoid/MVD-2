async function loadFc() {
  try {
    await loadLocalKeys('fc-user');
    const rows = await api('/api/fc/debug/showAll');
    createPager({
      rows,
      tbodyId: 'fc-body',
      searchId: 'fc-search',
      pagerId: 'fc-pager',
      columns: [
        { key: 'resource_id' },
        { key: 'user_id' },
        { key: 'description' },
        { key: 'endpoint' },
        { key: 'resource_path' },
      ],
    });
  } catch (e) { showResult(e); }
}

function fcPayload() {
  return {
    resource_id: val('resource-id'),
    user_id: val('fc-user'),
    description: val('description'),
    endpoint: val('endpoint'),
    resource_path: val('resource-path'),
  };
}

async function addFc() {
  try {
    showResult(await api('/api/console/fc/add', {
      method: 'POST',
      body: JSON.stringify(fcPayload()),
    }));
    await loadFc();
  } catch (e) { showResult(e); }
}

async function updateFc() {
  try {
    showResult(await api('/api/console/fc/update', {
      method: 'POST',
      body: JSON.stringify(fcPayload()),
    }));
    await loadFc();
  } catch (e) { showResult(e); }
}

async function deleteFc() {
  try {
    showResult(await api('/api/console/fc/delete', {
      method: 'POST',
      body: JSON.stringify({ resource_id: val('resource-id') }),
    }));
    await loadFc();
  } catch (e) { showResult(e); }
}

loadFc();
