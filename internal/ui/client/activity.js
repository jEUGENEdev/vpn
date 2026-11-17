'use strict';
const activityRows = new Map();
let activityExpanded = false;

function renderActivity() {
  const events = [...(state.events || [])].reverse();
  const searching = !!$('activity-search').value.trim();
  let matches = 0, shown = 0;
  reconcileRows($('activity-list'), events, e => e.at + ':' + e.id, activityRows,
    event => {
      const item = element('div', undefined, 'activity-item');
      item.append(element('strong'), element('p', '', 'event-message'), element('p', '', 'event-target'), element('p', '', 'event-source'));
      const details = element('details', undefined, 'source-details');
      details.append(element('summary', 'Подробнее об источнике'), element('p', '', 'application-path'));
      item.append(details, element('time'));
      if (event.kind === 'suggestion' && event.target) item.append(button('Рассмотреть адрес', 'secondary', () => approve(event.target)));
      if (event.kind === 'application') item.append(button('Открыть приложения', 'secondary', () => view('applications')));
      return item;
    },
    (item, event) => {
      const source = event.source;
      const origin = source ? 'Источник: ' + source.name : event.target ? 'Приложение-источник не определено' : 'Событие службы VPN';
      setText(item.querySelector('strong'), event.title);
      // Native notifications receive the full message. In the UI the context
      // has its own fields, keeping paths selectable and searchable on mobile.
      setText(item.querySelector('.event-message'), event.message.split('\nАдрес: ')[0]);
      setText(item.querySelector('.event-target'), event.target ? 'Адрес: ' + event.target : '');
      item.querySelector('.event-target').hidden = !event.target;
      setText(item.querySelector('.event-source'), origin);
      item.querySelector('.source-details').hidden = !source;
      setText(item.querySelector('.application-path'), source ? source.path + '\n' + source.platform : '');
      const time = item.querySelector('time');
      time.dateTime = event.at;
      setText(time, new Date(event.at).toLocaleString('ru', {day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit'}));
      const match = matchesSearch('activity-search', [event.target, event.title, event.message, origin, ...sourceFields(source ? [source] : [])]);
      if (match) matches++;
      item.hidden = !match || (!searching && !activityExpanded && shown >= 3);
      if (!item.hidden) shown++;
    }, true);
  empty($('activity-list'), 'Сеть работает по вашим правилам.');
  searchStatus('activity-search-status', searching ? matches : shown, events.length);
  $('activity-toggle').hidden = searching || events.length <= 3;
  $('activity-toggle').setAttribute('aria-expanded', String(activityExpanded));
  setText($('activity-toggle'), activityExpanded ? 'Свернуть историю' : 'Показать всю историю (' + events.length + ')');
}

function initActivity() {
  $('activity-search').oninput = renderActivity;
  $('activity-toggle').onclick = () => { activityExpanded = !activityExpanded; renderActivity(); };
}
