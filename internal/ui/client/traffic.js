'use strict';
const trafficRows = new Map(), applicationRows = new Map(), ruleRows = new Map(), deviceRows = new Map();
const promptedApplications = new Set();
let nextApplicationPrompt = 0, promptedApplication = null;

// Keep existing DOM nodes and their position. Polling may update counters, but
// must not move a button under the pointer, discard focus or collapse details.
function reconcileRows(list, values, keyOf, cache, create, patch, orderedInsert = false) {
  const keys = new Set(values.map(keyOf));
  for (const [key, node] of cache) if (!keys.has(key)) { node.remove(); cache.delete(key); }
  list.querySelectorAll(':scope > .empty').forEach(node => node.remove());
  for (const [index, value] of values.entries()) {
    const key = keyOf(value);
    let node = cache.get(key);
    if (!node) {
      node = create(value); node.dataset.key = key; cache.set(key, node);
      const next = orderedInsert && values.slice(index + 1).map(keyOf).map(key => cache.get(key)).find(Boolean);
      list.insertBefore(node, next || null);
    }
    patch(node, value);
  }
}
function setText(node, text) { if (node.textContent !== text) node.textContent = text; }
function matchesSearch(inputID, fields) {
  const words = $(inputID).value.trim().toLocaleLowerCase('ru').split(/\s+/).filter(Boolean);
  const text = fields.filter(value => value !== undefined && value !== null).join(' ').toLocaleLowerCase('ru');
  return words.every(word => text.includes(word));
}
function sourceFields(sources) { return (sources || []).flatMap(a => [a.id, a.name, a.path, a.platform]); }
function searchStatus(id, shown, total) {
  setText($(id), total ? (shown ? 'Показано: ' + shown + ' из ' + total : 'Ничего не найдено. Измените или очистите поиск.') : '');
}
function sourceSummary(sources, unknown) {
  const names = [...new Set((sources || []).map(source => source.name))];
  if (!names.length) return 'Приложение-источник не определено';
  return names.join(', ') + (unknown ? ' · есть запросы с неизвестным источником' : '');
}
function requestGroups() {
  return state.request_groups || (state.requests || []).filter(r => r.direct_failed).map(r => ({...r, requests:[r]}));
}
function trafficMatches(group) {
  return matchesSearch('traffic-search', [group.target, ...sourceFields(group.sources),
    ...(group.requests || []).flatMap(r => [r.target, ...sourceFields(r.sources)])]);
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
    r => {
      const node = row(r.target, '', [button('Разрешить адрес ↗', 'secondary', () => approve(r.target))]);
      const details = element('details', undefined, 'source-details');
      details.append(element('summary', 'Подробнее об источниках'), element('p', '', 'application-path'));
      node.querySelector('.row-copy').append(details);
      return node;
    },
    (node, r) => {
      const sources = r.sources || [];
      setText(node.querySelector('.row-copy p'), sourceSummary(sources, r.unknown_source));
      node.querySelector('.row-copy p').title = sources.map(a => a.name + ' — ' + a.path).join('\n');
      node.querySelector('.source-details').hidden = !sources.length;
      setText(node.querySelector('.application-path'), sources.map(a => a.name + ' · ' + a.platform + '\n' + a.path).join('\n\n'));
    });
  card.hidden = !trafficMatches(group);
}
function renderTraffic() {
  const groups = requestGroups();
  reconcileRows($('requests-list'), groups, g => g.target, trafficRows, buildRequestGroup, patchRequestGroup);
  empty($('requests-list'), 'Прямые подключения работают. Предложения появятся только после повторных ошибок или отсутствия ответа.');
  searchStatus('traffic-search-status', groups.filter(trafficMatches).length, groups.length);
  renderApplications();
}
async function decideApplication(app, decision) {
  if (decision === 'trusted' && !await confirmChange('Доверить VPN приложению «' + app.name + '»?', 'Весь трафик этого приложения пойдёт через VPN. При сбое VPN он сможет идти напрямую, без VPN-защиты. Правила адресов для остальных приложений не изменятся.\n' + app.path)) return;
  const result = await act('applications', {id:app.id, decision});
  toast(result.message || (state.vpn_enabled === false ? 'Решение сохранено. Оно начнёт действовать после включения VPN.' : decision === 'trusted' ? 'Приложение использует VPN' : 'Для приложения действуют правила адресов'));
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
      setText(card.querySelector('.row-copy p'), powerRouteNote('Решение') || (app.decision === 'trusted' ? (state.app_tunnel ? 'Доверенное · весь трафик через VPN' : 'Доверенное · VPN недоступен, используется прямое подключение') : app.decision === 'addresses' ? 'VPN только для разрешённых адресов' : 'Вы ещё не выбирали маршрут для приложения'));
      setText(card.querySelector('.application-target'), 'Последний адрес: ' + app.target);
      setText(card.querySelector('.application-path'), app.path);
      card.hidden = !matchesSearch('applications-search', [app.target, app.decision, ...sourceFields([app])]);
      card.querySelector('.primary').disabled = app.decision === 'trusted';
      card.querySelector('.secondary').disabled = app.decision === 'addresses';
    });
  empty($('applications-list'), 'Приложения появятся после первого сетевого подключения, если система позволит определить источник.');
  searchStatus('applications-search-status', [...applicationRows.values()].filter(node => !node.hidden).length, apps.length);
  maybePromptApplication();
}
function maybePromptApplication() {
	if ($('application-prompt').open && promptedApplication && !(state.pending_applications || []).some(a => a.id === promptedApplication.id)) {
		$('application-prompt').close('later');
		return;
	}
  if (state.vpn_enabled === false || !state.account_id || state.status === 'auth_required' || document.hidden || Date.now() < nextApplicationPrompt || document.querySelector('dialog[open]')) return;
  const app = (state.pending_applications || []).find(a => !promptedApplications.has(a.id));
  if (!app) return;
  promptedApplication = app;
  promptedApplications.add(app.id);
  $('application-title').textContent = 'Использовать «' + app.name + '» через VPN?';
  $('application-description').textContent = 'Вы ещё не выбирали VPN для этого приложения. Его запрос к ' + app.target + ' несколько раз не прошёл напрямую.';
  $('application-identity').textContent = app.path;
  $('application-prompt').returnValue = '';
  $('application-prompt').showModal();
}
function renderStableRules() {
  const pending = state.pending_protection || [];
  reconcileRows($('rules-list'), state.rules || [], target => target, ruleRows,
    target => {
      const node = row(target, '', [button('Повторить', 'primary', () => approve(target)), button('Удалить', 'secondary danger', async () => { if (await confirmChange('Убрать ' + target + '?', 'Адрес и не покрытые другими правилами поддомены смогут подключаться напрямую. Доверенные приложения продолжат использовать VPN.')) await act('rules', {target, action:'remove', revision:state.revision}); })]);
      const details = element('details', undefined, 'source-details');
      details.append(element('summary', 'Подробнее об источниках'), element('p', '', 'application-path'));
      node.querySelector('.row-copy').append(element('p', '', 'rule-sources'), details);
      return node;
    },
    (node, target) => {
      const traffic = (state.rule_sources || {})[target];
      const sources = traffic?.sources || [];
      setText(node.querySelector('.row-copy p'), powerRouteNote('Правило') || (pending.includes(target) ? 'Правило сохранено · сервер ещё не подтвердил' : 'VPN с прямым резервом · включая поддомены'));
      node.querySelector('.primary').hidden = !pending.includes(target);
      setText(node.querySelector('.rule-sources'), traffic ? 'Запросы с этого устройства: ' + sourceSummary(sources, traffic.unknown_source) : 'Запросов с этого устройства ещё не наблюдали');
      node.querySelector('.source-details').hidden = !sources.length;
      setText(node.querySelector('.application-path'), sources.map(a => a.name + ' · ' + a.platform + '\n' + a.path).join('\n\n'));
      node.hidden = !matchesSearch('rules-search', [target, ...sourceFields(sources)]);
    });
  empty($('rules-list'), 'Адреса ещё не разрешены. Доверенные приложения могут использовать VPN отдельно.');
  searchStatus('rules-search-status', [...ruleRows.values()].filter(node => !node.hidden).length, (state.rules || []).length);
}
function renderStableDevices() {
  reconcileRows($('devices-list'), state.devices || [], d => d.id, deviceRows,
    d => row(d.name, '', [button('Удалить устройство', 'secondary danger', async () => { if (await confirmChange('Удалить устройство?', 'Устройство исчезнет из списка. Его доступ к VPN, синхронизации и выданные им коды подключения будут отозваны. Для повторного подключения потребуется новый вход.')) await act('revoke', {id:d.id}); })]),
    (node, d) => { setText(node.querySelector('.row-copy strong'), d.name); setText(node.querySelector('.row-copy p'), (d.id === state.device_id ? 'Это устройство · ' : '') + d.platform + ' · ' + (d.revoked ? 'Доступ отозван' : 'До ' + new Date(d.expires).toLocaleDateString('ru'))); node.hidden = !matchesSearch('devices-search', [d.id, d.name, d.platform, node.querySelector('.row-copy p').textContent]); });
  empty($('devices-list'), 'Устройства пока не добавлены.');
  searchStatus('devices-search-status', [...deviceRows.values()].filter(node => !node.hidden).length, (state.devices || []).length);
}
function initTraffic() {
  $('traffic-search').oninput = renderTraffic;
  $('rules-search').oninput = renderStableRules;
  $('applications-search').oninput = renderApplications;
  $('devices-search').oninput = renderStableDevices;
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

function powerRouteNote(noun) {
  if(state.power_transition)return 'Переключаем сеть · '+noun+' сохранено';
  if(state.power_error)return 'Ошибка настройки сети · '+noun+' сохранено';
  if(state.status==='system_blocked')return 'Android блокирует интернет · '+noun+' сохранено';
  if(state.partial_fallback)return 'Часть адресов временно напрямую · '+noun+' сохранено';
  if(state.direct_fallback)return 'VPN недоступен · напрямую; '+noun.toLowerCase()+' сохранено';
  return state.vpn_enabled===false&&state.status==='disabled'?'VPN выключен · напрямую; '+noun.toLowerCase()+' сохранено':'';
}
