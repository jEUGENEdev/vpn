'use strict';
const trafficRows = new Map(), applicationRows = new Map(), ruleRows = new Map(), deviceRows = new Map();
const promptedApplications = new Set();
let nextApplicationPrompt = 0, promptedApplication = null;

// Keep existing DOM nodes and their position. Polling may update counters, but
// must not move a button under the pointer, discard focus or collapse details.
function reconcileRows(list, values, keyOf, cache, create, patch) {
  const keys = new Set(values.map(keyOf));
  for (const [key, node] of cache) if (!keys.has(key)) { node.remove(); cache.delete(key); }
  list.querySelectorAll(':scope > .empty').forEach(node => node.remove());
  for (const value of values) {
    const key = keyOf(value);
    let node = cache.get(key);
    if (!node) { node = create(value); node.dataset.key = key; cache.set(key, node); list.append(node); }
    patch(node, value);
  }
}
function setText(node, text) { if (node.textContent !== text) node.textContent = text; }
function sourceSummary(sources, unknown) {
  const names = [...new Set((sources || []).map(source => source.name))];
  if (!names.length) return 'Приложение-источник не определено';
  return names.join(', ') + (unknown ? ' · есть запросы с неизвестным источником' : '');
}
function requestGroups() {
  return state.request_groups || (state.requests || []).filter(r => r.direct_failed).map(r => ({...r, requests:[r]}));
}
function trafficMatches(group) {
  const query = $('traffic-search').value.trim().toLocaleLowerCase('ru');
  return !query || [group.target, ...(group.requests || []).map(r => r.target), ...(group.sources || []).flatMap(a => [a.name, a.path])].join(' ').toLocaleLowerCase('ru').includes(query);
}
function buildRequestGroup(group) {
  const card = element('div', undefined, 'request-group');
  const header = row(group.target, '', [button('Разрешить VPN ↗', 'primary', () => approve(group.target)), button('Оставить напрямую', 'secondary', () => act('dismiss', {target:group.target}))]);
  const sources = element('p', '', 'request-sources');
  const details = element('details', undefined, 'request-details');
  details.append(element('summary', 'Адреса и приложения'), element('div', undefined, 'target-list'));
  card.append(header, sources, details);
  card.targetRows = new Map();
  return card;
}
function patchRequestGroup(card, group) {
  const entries = group.requests || [];
  setText(card.querySelector('.row-copy p'), 'Нет ответа напрямую · адресов: ' + entries.length + ' · наблюдений: ' + group.count);
  setText(card.querySelector('.request-sources'), sourceSummary(group.sources, group.unknown_source));
  setText(card.querySelector('summary'), 'Адреса и приложения (' + entries.length + ')');
  reconcileRows(card.querySelector('.target-list'), entries, r => r.target, card.targetRows,
    r => row(r.target, '', [button('Разрешить адрес ↗', 'secondary', () => approve(r.target))]),
    (node, r) => {
      const sources = r.sources || [];
      setText(node.querySelector('.row-copy p'), sourceSummary(sources, r.unknown_source));
      node.querySelector('.row-copy p').title = sources.map(a => a.name + ' — ' + a.path).join('\n');
    });
  card.hidden = !trafficMatches(group);
}
function renderTraffic() {
  const groups = requestGroups();
  reconcileRows($('requests-list'), groups, g => g.target, trafficRows, buildRequestGroup, patchRequestGroup);
  empty($('requests-list'), 'Прямые подключения работают. Предложения появятся только после повторных ошибок или отсутствия ответа.');
  $('traffic-empty-search').hidden = !groups.length || groups.some(trafficMatches);
  renderApplications();
}
async function decideApplication(app, decision) {
  if (decision === 'trusted' && !await confirmChange('Доверить VPN приложению «' + app.name + '»?', 'Весь трафик этого приложения пойдёт через VPN. При сбое VPN он будет заблокирован. Правила адресов для остальных приложений не изменятся.\n' + app.path)) return;
  const result = await act('applications', {id:app.id, decision});
  toast(result.message || (decision === 'trusted' ? 'Приложение использует VPN' : 'Для приложения действуют правила адресов'));
}
function renderApplications() {
  const apps = state.applications || [];
  $('application-count').textContent = (state.pending_applications || []).length;
  $('attribution-note').hidden = !!state.attribution_available;
  reconcileRows($('applications-list'), apps, a => a.id, applicationRows,
    app => {
      const card = row(app.name, '', [button('Доверить весь трафик', 'primary', () => decideApplication(app, 'trusted')), button('Только по адресам', 'secondary', () => decideApplication(app, 'addresses'))]);
      card.querySelector('.row-copy').append(element('p', app.path, 'application-path'), element('p', '', 'application-target'));
      return card;
    },
    (card, app) => {
      setText(card.querySelector('.row-copy strong'), app.name);
      setText(card.querySelector('.row-copy p'), app.decision === 'trusted' ? (state.app_tunnel ? 'Доверенное · весь трафик через VPN' : 'Доверенное · ждём сервер, прямого обхода нет') : app.decision === 'addresses' ? 'VPN только для разрешённых адресов' : 'Вы ещё не выбирали маршрут для приложения');
      setText(card.querySelector('.application-target'), 'Последний адрес: ' + app.target);
      card.querySelector('.primary').disabled = app.decision === 'trusted';
      card.querySelector('.secondary').disabled = app.decision === 'addresses';
    });
  empty($('applications-list'), 'Приложения появятся после первого сетевого подключения, если система позволит определить источник.');
  maybePromptApplication();
}
function maybePromptApplication() {
	if ($('application-prompt').open && promptedApplication && !(state.pending_applications || []).some(a => a.id === promptedApplication.id)) {
		$('application-prompt').close('later');
		return;
	}
  if (!state.account_id || state.status === 'auth_required' || document.hidden || Date.now() < nextApplicationPrompt || document.querySelector('dialog[open]')) return;
  const app = (state.pending_applications || []).find(a => !promptedApplications.has(a.id));
  if (!app) return;
  promptedApplication = app;
  promptedApplications.add(app.id);
  $('application-title').textContent = 'Использовать «' + app.name + '» через VPN?';
  $('application-description').textContent = 'Вы ещё не выбирали VPN для этого приложения. Его запрос к ' + app.target + ' несколько раз не прошёл напрямую.';
  $('application-identity').textContent = app.path;
  $('application-prompt').showModal();
}
function renderStableRules() {
  const pending = state.pending_protection || [];
  reconcileRows($('rules-list'), state.rules || [], target => target, ruleRows,
    target => row(target, '', [button('Повторить', 'primary', () => approve(target)), button('Удалить', 'secondary danger', async () => { if (await confirmChange('Убрать ' + target + '?', 'Адрес и не покрытые другими правилами поддомены смогут подключаться напрямую. Доверенные приложения продолжат использовать VPN.')) await act('rules', {target, action:'remove', revision:state.revision}); })]),
    (node, target) => { setText(node.querySelector('.row-copy p'), pending.includes(target) ? 'Локальная защита включена · сервер ещё не подтвердил' : 'Только VPN · включая поддомены'); node.querySelector('.primary').hidden = !pending.includes(target); });
  empty($('rules-list'), 'Адреса ещё не разрешены. Доверенные приложения могут использовать VPN отдельно.');
}
function renderStableDevices() {
  reconcileRows($('devices-list'), state.devices || [], d => d.id, deviceRows,
    d => row(d.name, '', [button('Отозвать доступ', 'secondary danger', async () => { if (await confirmChange('Отозвать доступ?', 'Устройство потеряет доступ к VPN и синхронизации.')) await act('revoke', {id:d.id}); })]),
    (node, d) => { setText(node.querySelector('.row-copy strong'), d.name); setText(node.querySelector('.row-copy p'), (d.id === state.device_id ? 'Это устройство · ' : '') + d.platform + ' · ' + (d.revoked ? 'Доступ отозван' : 'До ' + new Date(d.expires).toLocaleDateString('ru'))); });
}
function initTraffic() {
  $('traffic-search').oninput = renderTraffic;
  $('application-prompt').addEventListener('close', async () => {
    const app = promptedApplication, decision = $('application-prompt').returnValue;
    promptedApplication = null;
    nextApplicationPrompt = Date.now() + 60000;
    if (!app || !['trusted', 'addresses'].includes(decision)) return;
    try {
      const result = await act('applications', {id:app.id, decision});
      toast(result.message || (decision === 'trusted' ? 'Приложение использует VPN' : 'Оставили выбор по адресам'));
    } catch { /* act displays the error; the decision can be retried on Applications. */ }
  });
  document.addEventListener('visibilitychange', maybePromptApplication);
}
