'use strict';
// Proculus web UI. Everything shown comes from scanned networks (titles,
// banners, host names) and is untrusted: it is only ever put on the page with
// textContent / text nodes, never as HTML.

// ---------------------------------------------------------------- texts
const TEXTS = {
  pl: {
    dashboard: 'Dashboard', services: 'Usługi', runs: 'Skany', changes: 'Zmiany', add: 'Dodaj dane', admin: 'Administracja', soon: 'wkrótce',
    latest: 'najnowszy', loading: 'Ładowanie…', error: 'Błąd', noRuns: 'Brak zapisanych skanów.',
    noRunsHint: 'Uruchom skan (np. gateway --store results) i odśwież stronę.',
    lastRun: 'Ostatni skan', started: 'Start', source: 'Źródło', hosts: 'Hosty', servicesN: 'Usługi', webServices: 'Usługi webowe', detections: 'Wykrycia',
    sinceLast: 'Zmiany względem poprzedniego skanu', firstRun: 'To pierwszy skan: nie ma z czym porównać.',
    newHosts: 'Nowe hosty', goneHosts: 'Zniknęły hosty', newServices: 'Nowe usługi', goneServices: 'Usunięte usługi', changedServices: 'Zmienione usługi', webChanges: 'Zmiany webowe',
    topFindings: 'Najważniejsze znaleziska', noFindings: 'Brak znalezisk wymagających uwagi.',
    byLevel: 'Usługi wg priorytetu', byCategory: 'Wykrycia wg kategorii', technologies: 'Najczęstsze technologie', hostStates: 'Stan hostów (w czasie)', attention: 'Wymagają uwagi',
    high: 'wysoki', medium: 'średni', low: 'niski', info: 'info',
    score: 'Priorytet', address: 'Adres', hostname: 'Nazwa', service: 'Usługa', title: 'Tytuł', why: 'Dlaczego', found: 'Wykryto',
    search: 'Szukaj (adres, nazwa, usługa, tytuł, technologia)…', minScore: 'Priorytet od', any: 'dowolny', run: 'Skan',
    prev: 'Poprzednia', next: 'Następna', of: 'z', none: 'brak wyników',
    id: 'Nr', finished: 'Koniec', open: 'Usługi', compare: 'Porównaj z poprzednim',
    before: 'Przed', after: 'Po', show: 'Pokaż', pickTwo: 'Wybierz dwa różne skany.', what: 'Co', was: 'Było', is: 'Jest', noChanges: 'Bez zmian.',
    state_new: 'nowe', state_active: 'aktywne', state_flapping: 'niestabilne', state_stale: 'nieaktywne?', state_gone: 'zniknęły',
    existence: 'Pewność istnienia', seen: 'Widziany', timeDep: 'zależny od pory dnia',
  },
  en: {
    dashboard: 'Dashboard', services: 'Services', runs: 'Runs', changes: 'Changes', add: 'Add data', admin: 'Administration', soon: 'coming soon',
    latest: 'latest', loading: 'Loading…', error: 'Error', noRuns: 'No saved runs yet.',
    noRunsHint: 'Run a scan (e.g. gateway --store results) and reload.',
    lastRun: 'Latest run', started: 'Started', source: 'Source', hosts: 'Hosts', servicesN: 'Services', webServices: 'Web services', detections: 'Detections',
    sinceLast: 'Changes since the previous run', firstRun: 'This is the first run: nothing to compare with.',
    newHosts: 'New hosts', goneHosts: 'Hosts gone', newServices: 'New services', goneServices: 'Services gone', changedServices: 'Changed services', webChanges: 'Web changes',
    topFindings: 'Top findings', noFindings: 'Nothing needs attention.',
    byLevel: 'Services by priority', byCategory: 'Detections by category', technologies: 'Most common technologies', hostStates: 'Host states (over time)', attention: 'Needs attention',
    high: 'high', medium: 'medium', low: 'low', info: 'info',
    score: 'Priority', address: 'Address', hostname: 'Name', service: 'Service', title: 'Title', why: 'Why', found: 'Detected',
    search: 'Search (address, name, service, title, technology)…', minScore: 'Priority from', any: 'any', run: 'Run',
    prev: 'Previous', next: 'Next', of: 'of', none: 'no results',
    id: 'No.', finished: 'Finished', open: 'Services', compare: 'Compare with previous',
    before: 'Before', after: 'After', show: 'Show', pickTwo: 'Choose two different runs.', what: 'What', was: 'Was', is: 'Is', noChanges: 'No changes.',
    state_new: 'new', state_active: 'active', state_flapping: 'flapping', state_stale: 'stale', state_gone: 'gone',
    existence: 'Existence confidence', seen: 'Seen', timeDep: 'time-of-day dependent',
  },
};

let lang = 'pl';
try { const saved = localStorage.getItem('proculus.lang'); if (saved === 'pl' || saved === 'en') lang = saved; } catch (e) { /* storage may be unavailable */ }
const t = (k) => (TEXTS[lang] && TEXTS[lang][k]) || k;

// ---------------------------------------------------------------- helpers
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === undefined || kid === null || kid === false) continue;
    e.appendChild(typeof kid === 'object' ? kid : document.createTextNode(String(kid)));
  }
  return e;
}

async function api(path) {
  const r = await fetch(path, { headers: { Accept: 'application/json' } });
  let body = null;
  try { body = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new Error((body && body.error) || ('HTTP ' + r.status));
  return body;
}

const qs = (o) => Object.entries(o).filter(([, v]) => v !== '' && v !== undefined && v !== null).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
const when = (iso) => (iso || '').replace('T', ' ').replace(/:\d\dZ$/, 'Z');
const go = (route, params) => { location.hash = '#/' + route + (params && qs(params) ? '?' + qs(params) : ''); };

function badge(score, level) { return el('span', { class: 'badge ' + level, title: t(level) }, String(score)); }

function stat(label, value, delta) {
  return el('div', { class: 'card stat' }, el('div', { class: 'n' }, String(value)), el('div', { class: 'l' }, label), delta);
}

function bars(rows, nameOf, level) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return rows.length ? rows.map((r) => el('div', { class: 'bar-row' },
    el('span', { class: 'lbl', title: nameOf(r) }, nameOf(r)),
    el('div', { class: 'bar ' + (level ? level(r) : '') }, el('i', { style: 'width:' + Math.round(100 * r.count / max) + '%' })),
    el('span', {}, String(r.count)))) : el('p', { class: 'sub' }, '—');
}

function serviceRow(f, onclick) {
  return el('tr', onclick ? { class: 'click', onclick } : {},
    el('td', {}, badge(f.score, f.level)),
    el('td', { class: 'mono' }, f.ip + ':' + f.port + '/' + f.protocol),
    el('td', {}, f.hostname),
    el('td', {}, f.service),
    el('td', {}, f.title),
    el('td', {}, f.detections.map((d) => el('span', { class: 'chip' }, d))),
    el('td', {}, f.reasons.length ? el('ul', { class: 'reasons' }, f.reasons.map((r) => el('li', {}, r))) : ''));
}

function servicesHead() {
  return el('thead', {}, el('tr', {}, ['score', 'address', 'hostname', 'service', 'title', 'found', 'why'].map((k) => el('th', {}, t(k)))));
}

// ---------------------------------------------------------------- views
async function viewDashboard() {
  const d = await api('/api/dashboard');
  if (d.empty) return el('div', { class: 'card empty' }, el('h2', {}, t('noRuns')), el('p', {}, t('noRunsHint')));

  const delta = (n, goodWhenUp) => el('div', { class: 'd ' + (n === 0 ? 'flat' : (n > 0) === goodWhenUp ? 'up' : 'down') }, (n > 0 ? '+' : '') + n);
  const ch = d.changes;
  const hosts = await api('/api/hosts').catch(() => null);

  const changeCards = ch ? el('div', { class: 'grid' },
    stat(t('newHosts'), ch.new_hosts), stat(t('goneHosts'), ch.gone_hosts), stat(t('newServices'), ch.new_services),
    stat(t('goneServices'), ch.gone_services), stat(t('changedServices'), ch.changed_services),
    stat(t('webChanges'), ch.web_changes)) : el('p', { class: 'sub' }, t('firstRun'));

  const levelRows = d.levels.map((l) => ({ name: t(l.level), count: l.count, level: l.level }));

  return el('div', {},
    el('h1', {}, t('dashboard')),
    el('p', { class: 'sub' }, t('lastRun') + ' #' + d.run.id + ' · ' + t('started') + ' ' + when(d.run.started) + ' · ' + t('source') + ': ' + d.run.source),
    el('div', { class: 'grid' },
      stat(t('hosts'), d.run.hosts, d.previous ? delta(d.run.hosts - d.previous.hosts, true) : null),
      stat(t('servicesN'), d.run.services, d.previous ? delta(d.run.services - d.previous.services, true) : null),
      stat(t('webServices'), d.web_services), stat(t('detections'), d.detections)),
    el('h2', {}, t('sinceLast')), changeCards,
    el('div', { class: 'cols' },
      el('div', { class: 'card' }, el('h2', {}, t('byLevel')), bars(levelRows, (r) => r.name, (r) => r.level)),
      el('div', { class: 'card' }, el('h2', {}, t('byCategory')), bars(d.categories, (r) => r.category)),
      el('div', { class: 'card' }, el('h2', {}, t('technologies')), bars(d.technologies, (r) => r.name))),
    el('div', { class: 'card' }, el('h2', {}, t('topFindings')),
      d.top.length ? el('table', {}, servicesHead(), el('tbody', {}, d.top.map((f) => serviceRow(f, () => go('services', { q: f.ip }))))) : el('p', { class: 'sub' }, t('noFindings'))),
    hosts ? hostStates(hosts) : null);
}

function hostStates(h) {
  const names = ['new', 'active', 'flapping', 'stale', 'gone'];
  return el('div', { class: 'card', style: 'margin-top:14px' },
    el('h2', {}, t('hostStates')),
    el('div', {}, names.map((n) => el('span', { class: 'chip state-' + n }, t('state_' + n) + ': ' + (h.counts[n] || 0)))),
    h.attention.length ? el('div', { style: 'margin-top:10px' }, el('h2', {}, t('attention')),
      el('table', {}, el('thead', {}, el('tr', {}, ['address', 'hostname', 'score'].map((k) => el('th', {}, k === 'score' ? t('existence') : t(k))), el('th', {}, t('seen')))),
        el('tbody', {}, h.attention.map((a) => el('tr', {},
          el('td', { class: 'mono' }, a.ip), el('td', {}, a.hostname),
          el('td', {}, el('span', { class: 'state-' + a.state }, t('state_' + a.state)), ' ', Math.round(a.existence * 100) + '%' + (a.time_dependent ? ' · ' + t('timeDep') : '')),
          el('td', {}, a.sightings + '/' + a.observations)))))) : null);
}

async function viewServices(params) {
  const runs = await api('/api/runs');
  if (!runs.length) return el('div', { class: 'card empty' }, el('h2', {}, t('noRuns')), el('p', {}, t('noRunsHint')));
  const state = { run: params.run || 'latest', q: params.q || '', min: params.min || '0', offset: Number(params.offset || 0) };
  const out = el('div', {});
  const table = el('div', {});

  async function load() {
    table.replaceChildren(el('p', { class: 'sub' }, t('loading')));
    try {
      const r = await api('/api/services?' + qs({ run: state.run, q: state.q, min_score: state.min === '0' ? '' : state.min, limit: 50, offset: state.offset }));
      const from = r.total ? r.offset + 1 : 0, to = Math.min(r.offset + r.limit, r.total);
      table.replaceChildren(
        r.services.length ? el('table', {}, servicesHead(), el('tbody', {}, r.services.map((f) => serviceRow(f)))) : el('div', { class: 'empty' }, t('none')),
        el('div', { class: 'pager' },
          el('span', {}, from + '–' + to + ' ' + t('of') + ' ' + r.total),
          el('button', { disabled: r.offset === 0, onclick: () => { state.offset = Math.max(0, state.offset - r.limit); load(); } }, t('prev')),
          el('button', { disabled: to >= r.total, onclick: () => { state.offset += r.limit; load(); } }, t('next'))));
    } catch (e) { table.replaceChildren(el('div', { class: 'err' }, t('error') + ': ' + e.message)); }
  }

  const runSel = el('select', { onchange: (e) => { state.run = e.target.value; state.offset = 0; load(); } },
    el('option', { value: 'latest' }, t('run') + ': ' + t('latest')), runs.map((r) => el('option', { value: String(r.id), selected: String(r.id) === state.run }, t('run') + ' #' + r.id + ' · ' + when(r.started))));
  const search = el('input', { class: 'grow', type: 'search', placeholder: t('search'), value: state.q });
  let timer = null;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { state.q = search.value.trim(); state.offset = 0; load(); }, 250); });
  const minSel = el('select', { onchange: (e) => { state.min = e.target.value; state.offset = 0; load(); } },
    [['0', t('any')], ['15', '≥ 15 (' + t('low') + ')'], ['40', '≥ 40 (' + t('medium') + ')'], ['70', '≥ 70 (' + t('high') + ')']].map(([v, l]) => el('option', { value: v, selected: v === state.min }, t('minScore') + ': ' + l)));

  out.append(el('h1', {}, t('services')), el('div', { class: 'toolbar' }, search, minSel, runSel), el('div', { class: 'card' }, table));
  load();
  return out;
}

async function viewRuns() {
  const runs = await api('/api/runs');
  if (!runs.length) return el('div', { class: 'card empty' }, el('h2', {}, t('noRuns')), el('p', {}, t('noRunsHint')));
  return el('div', {}, el('h1', {}, t('runs')), el('div', { class: 'card' }, el('table', {},
    el('thead', {}, el('tr', {}, ['id', 'started', 'finished', 'source', 'hosts', 'servicesN', ''].map((k) => el('th', {}, k ? t(k) : '')))),
    el('tbody', {}, runs.map((r, i) => el('tr', {},
      el('td', {}, '#' + r.id), el('td', {}, when(r.started)), el('td', {}, when(r.finished)), el('td', {}, r.source), el('td', {}, String(r.hosts)), el('td', {}, String(r.services)),
      el('td', {}, el('button', { onclick: () => go('services', { run: r.id }) }, t('open')), ' ',
        i + 1 < runs.length ? el('button', { onclick: () => go('changes', { before: runs[i + 1].id, after: r.id }) }, t('compare')) : null)))))));
}

async function viewChanges(params) {
  const runs = await api('/api/runs');
  if (runs.length < 2) return el('div', { class: 'card empty' }, el('h2', {}, t('changes')), el('p', {}, t('pickTwo')));
  const before = params.before || String(runs[1].id), after = params.after || String(runs[0].id);
  const pick = (name, value) => el('select', { id: name }, runs.map((r) => el('option', { value: String(r.id), selected: String(r.id) === value }, '#' + r.id + ' · ' + when(r.started))));
  const selB = pick('before', before), selA = pick('after', after);
  const result = el('div', {});
  const key = (c) => c.ip + ':' + c.port + '/' + c.protocol;

  const LIMIT = 100;
  const more = (rows) => rows.length > LIMIT ? el('p', { class: 'sub' }, '… +' + (rows.length - LIMIT)) : null;
  const card = (title, cls, rows, body) => el('div', { class: 'card', style: 'margin-bottom:14px' }, el('h2', { class: cls }, title + ' (' + rows.length + ')'), body, more(rows));
  const list = (title, cls, rows, render) => rows.length ? card(title, cls, rows, el('table', {}, el('tbody', {}, rows.slice(0, LIMIT).map(render)))) : null;
  const chips = (title, cls, rows) => rows.length ? card(title, cls, rows, el('div', {}, rows.slice(0, LIMIT * 3).map((h) => el('span', { class: 'chip mono' }, h)))) : null;

  try {
    if (before !== after) {
      const d = await api('/api/diff?' + qs({ before, after }));
      const none = !d.new_hosts.length && !d.gone_hosts.length && !d.new_services.length && !d.gone_services.length && !d.changed_services.length && !d.web_changes.length;
      const sections = [
        chips(t('newHosts'), 'tag-new', d.new_hosts),
        chips(t('goneHosts'), 'tag-gone', d.gone_hosts),
        list(t('newServices'), 'tag-new', d.new_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.after))),
        list(t('goneServices'), 'tag-gone', d.gone_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.before))),
        list(t('changedServices'), 'tag-chg', d.changed_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.before + ' → ' + s.after))),
        list(t('webChanges'), 'tag-chg', d.web_changes, (w) => el('tr', {}, el('td', { class: 'mono' }, key(w)), el('td', {}, w.what), el('td', {}, w.before || '—'), el('td', {}, '→ ' + (w.after || '—')))),
      ].filter(Boolean);
      result.append(...(none ? [el('div', { class: 'card empty' }, t('noChanges'))] : sections));
    } else result.append(el('div', { class: 'card empty' }, t('pickTwo')));
  } catch (e) { result.append(el('div', { class: 'err' }, t('error') + ': ' + e.message)); }

  return el('div', {}, el('h1', {}, t('changes')),
    el('div', { class: 'toolbar' }, t('before'), selB, t('after'), selA, el('button', { onclick: () => go('changes', { before: selB.value, after: selA.value }) }, t('show'))),
    result);
}

// ---------------------------------------------------------------- shell
const ROUTES = { dashboard: viewDashboard, services: viewServices, runs: viewRuns, changes: viewChanges };

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [name, query] = raw.split('?');
  const params = {};
  for (const part of (query || '').split('&')) {
    if (!part) continue;
    const [k, v] = part.split('=');
    try { params[decodeURIComponent(k)] = decodeURIComponent(v || ''); } catch (e) { /* ignore a malformed pair */ }
  }
  return { name: ROUTES[name] ? name : 'dashboard', params };
}

function renderNav(active) {
  const nav = document.getElementById('nav');
  nav.replaceChildren(
    ...Object.keys(ROUTES).map((n) => el('a', { href: '#/' + n, class: n === active ? 'active' : '' }, t(n))),
    // placeholders for the next steps (forms, users and roles)
    el('span', { class: 'soon', title: t('soon') }, t('add')),
    el('span', { class: 'soon', title: t('soon') }, t('admin')));
}

let renderToken = 0;
async function render() {
  const token = ++renderToken;
  const { name, params } = parseHash();
  renderNav(name);
  document.documentElement.lang = lang;
  const view = document.getElementById('view');
  view.replaceChildren(el('p', { class: 'sub' }, t('loading')));
  try {
    const node = await ROUTES[name](params);
    if (token === renderToken) view.replaceChildren(node);
  } catch (e) {
    if (token === renderToken) view.replaceChildren(el('div', { class: 'err' }, t('error') + ': ' + e.message));
  }
}

const langSel = document.getElementById('lang');
langSel.value = lang;
langSel.addEventListener('change', () => {
  lang = langSel.value;
  try { localStorage.setItem('proculus.lang', lang); } catch (e) { /* ignore */ }
  render();
});
window.addEventListener('hashchange', render);
render();
