'use strict';
// Proculus web UI. Everything shown comes from scanned networks (titles,
// banners, host names) and is untrusted: it is only ever put on the page with
// textContent / text nodes, never as HTML.

// ---------------------------------------------------------------- texts
const TEXTS = {
  pl: {
    dashboard: 'Dashboard', services: 'Usługi', runs: 'Skany', changes: 'Zmiany', add: 'Dodaj dane', admin: 'Administracja', soon: 'wkrótce',
    scan: 'Nowy skan', scanTitle: 'Nowy skan', scanDisabled: 'Uruchamianie skanów z interfejsu jest wyłączone na tym serwerze.',
    scanDisabledHint: 'Operator włącza je przy starcie bramy: gateway serve --enable-scans --scan-scope SIEĆ --scan-ports PORTY',
    limits: 'Limity ustawione przez operatora', scope: 'Zakres', allowedPorts: 'Dozwolone porty', maxWorkers: 'maks. procesów', maxRate: 'maks. pakietów/s',
    targets: 'Cele', targetsHint: 'Po jednym w linii: adres IP, CIDR, zakres lub domena', exclusions: 'Wyłączenia', exclusionsHint: 'Adresy, które nigdy nie będą skanowane',
    ports: 'Porty usług', portsHint: 'Puste = wszystkie dozwolone porty', workers: 'Procesy nmap', rate: 'Pakietów/s na proces', timing: 'Tempo nmap (-T)',
    web: 'Sondowanie usług webowych i wykrywanie technologii', privileged: 'Skan z surowymi gniazdami (SYN, ICMP; wymaga uprawnień)',
    token: 'Token sterowania', tokenHint: 'Wypisany w konsoli przy starcie bramy; potrzebny do uruchamiania i zatrzymywania skanów',
    plan: 'Pokaż plan', start: 'Uruchom skan', stop: 'Zatrzymaj skan', planResult: 'Plan', addresses: 'adresów do przeskanowania', chunksN: 'porcji', estimate: 'szac. czas wykrywania',
    excluded: 'wyłączonych', domainsN: 'domen do rozwiązania',
    running: 'Skan w toku', stopping: 'Zatrzymywanie…', stage: 'Etap', hostsFound: 'Znalezione hosty', elapsed: 'Czas', chunksDone: 'porcje', pausesN: 'pauzy',
    log: 'Dziennik', lastScan: 'Ostatni skan z interfejsu', finishedAt: 'Zakończono', savedAs: 'zapisany jako skan', openRun: 'Zobacz usługi', scanOk: 'Zakończony', scanFailed: 'Nieudany',
    warnings: 'Ostrzeżenia', scanInProgress: 'Trwa skan', seconds: 's', started_ok: 'Skan uruchomiony.',
    setupTitle: 'Pierwsze uruchomienie', setupIntro: 'Nie ma jeszcze żadnych kont. Utwórz konto administratora.', setupToken: 'Token instalacji',
    setupTokenHint: 'Wypisany w konsoli bramy (gateway serve) przy starcie. Chroni przed tym, by ktoś inny założył konto pierwszy.', confirmPassword: 'Powtórz hasło',
    passwordsDiffer: 'Hasła się różnią.', createAdmin: 'Utwórz administratora',
    openMode: 'Logowanie jest wyłączone na tym serwerze (--no-auth): każdy, kto ma dostęp do tej strony, widzi wszystkie dane.',
    save: 'Zapisz', login: 'Zaloguj się', username: 'Użytkownik', password: 'Hasło', signIn: 'Zaloguj', signOut: 'Wyloguj', noUsers: 'Nie ma jeszcze żadnych kont.',
    noUsersHint: 'Utwórz pierwszego administratora poleceniem: gateway user add TWOJA.NAZWA --role admin', forbidden: 'Twoja rola nie ma dostępu do tej strony.',
    adminTitle: 'Administracja', users: 'Użytkownicy', roles: 'Role', audit: 'Dziennik zdarzeń', role: 'Rola', status: 'Status', lastLogin: 'Ostatnie logowanie', actions: 'Akcje',
    enabled: 'aktywne', disabled: 'wyłączone', disable: 'Wyłącz', enable: 'Włącz', resetPassword: 'Zmień hasło', newPassword: 'Nowe hasło (min. 10 znaków)', addUser: 'Dodaj użytkownika',
    never: 'nigdy', permissions: 'Uprawnienia', description: 'Opis', addRole: 'Dodaj rolę', roleName: 'Nazwa roli (małe litery)', deleteRole: 'Usuń', builtin: 'wbudowana',
    when_: 'Kiedy', who: 'Kto', action: 'Akcja', entity: 'Obiekt', detail: 'Szczegóły', saved: 'Zapisano.', authOff: 'Logowanie jest wyłączone na tym serwerze (uruchom bramę z opcją --auth).',
    role_admin: 'Administracja', role_manager: 'Dodawanie, usuwanie, modyfikacja', role_editor: 'Modyfikacja i odczyt', role_viewer: 'Odczyt',
    'perm_data.read': 'odczyt danych', 'perm_data.edit': 'modyfikacja danych', 'perm_data.create': 'dodawanie danych', 'perm_data.delete': 'usuwanie danych', perm_export: 'eksport',
    'perm_scan.run': 'uruchamianie skanów', 'perm_config.manage': 'konfiguracja', 'perm_users.manage': 'zarządzanie użytkownikami',
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
    scan: 'New scan', scanTitle: 'New scan', scanDisabled: 'Starting scans from the UI is turned off on this server.',
    scanDisabledHint: 'The operator enables it when starting the gateway: gateway serve --enable-scans --scan-scope NETWORK --scan-ports PORTS',
    limits: 'Limits set by the operator', scope: 'Scope', allowedPorts: 'Allowed ports', maxWorkers: 'max processes', maxRate: 'max packets/s',
    targets: 'Targets', targetsHint: 'One per line: IP address, CIDR, range or domain', exclusions: 'Exclusions', exclusionsHint: 'Addresses that are never scanned',
    ports: 'Service ports', portsHint: 'Empty = every allowed port', workers: 'nmap processes', rate: 'Packets/s per process', timing: 'nmap timing (-T)',
    web: 'Probe web services and detect technologies', privileged: 'Raw-socket scan (SYN, ICMP; needs privileges)',
    token: 'Control token', tokenHint: 'Printed in the console when the gateway starts; needed to start and stop scans',
    plan: 'Show plan', start: 'Start scan', stop: 'Stop scan', planResult: 'Plan', addresses: 'addresses to scan', chunksN: 'chunks', estimate: 'estimated discovery time',
    excluded: 'excluded', domainsN: 'domains to resolve',
    running: 'Scan in progress', stopping: 'Stopping…', stage: 'Stage', hostsFound: 'Hosts found', elapsed: 'Elapsed', chunksDone: 'chunks', pausesN: 'pauses',
    log: 'Log', lastScan: 'Last scan from the UI', finishedAt: 'Finished', savedAs: 'saved as run', openRun: 'View services', scanOk: 'Finished', scanFailed: 'Failed',
    warnings: 'Warnings', scanInProgress: 'A scan is running', seconds: 's', started_ok: 'Scan started.',
    setupTitle: 'First-run setup', setupIntro: 'There are no accounts yet. Create the administrator account.', setupToken: 'Setup token',
    setupTokenHint: 'Printed on the gateway console (gateway serve) at startup. It stops anyone else from creating the first account before you.', confirmPassword: 'Repeat password',
    passwordsDiffer: 'The passwords differ.', createAdmin: 'Create administrator',
    openMode: 'Login is turned off on this server (--no-auth): anyone who can reach this page can see all the data.',
    save: 'Save', login: 'Sign in', username: 'User name', password: 'Password', signIn: 'Sign in', signOut: 'Sign out', noUsers: 'There are no accounts yet.',
    noUsersHint: 'Create the first administrator with: gateway user add YOUR.NAME --role admin', forbidden: 'Your role has no access to this page.',
    adminTitle: 'Administration', users: 'Users', roles: 'Roles', audit: 'Audit log', role: 'Role', status: 'Status', lastLogin: 'Last login', actions: 'Actions',
    enabled: 'enabled', disabled: 'disabled', disable: 'Disable', enable: 'Enable', resetPassword: 'Reset password', newPassword: 'New password (at least 10 characters)', addUser: 'Add user',
    never: 'never', permissions: 'Permissions', description: 'Description', addRole: 'Add role', roleName: 'Role name (lowercase)', deleteRole: 'Delete', builtin: 'built in',
    when_: 'When', who: 'Who', action: 'Action', entity: 'Object', detail: 'Details', saved: 'Saved.', authOff: 'Login is turned off on this server (start the gateway with --auth).',
    role_admin: 'Administration', role_manager: 'Add, delete and modify', role_editor: 'Modify and read', role_viewer: 'Read only',
    'perm_data.read': 'read data', 'perm_data.edit': 'modify data', 'perm_data.create': 'add data', 'perm_data.delete': 'delete data', perm_export: 'export',
    'perm_scan.run': 'run scans', 'perm_config.manage': 'configuration', 'perm_users.manage': 'manage users',
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

function authHeaders(h) {
  if (session.token) h['X-Proculus-Session'] = session.token;
  return h;
}

async function api(path) {
  const r = await fetch(path, { headers: authHeaders({ Accept: 'application/json' }) });
  let body = null;
  try { body = await r.json(); } catch (e) { /* not JSON */ }
  if (r.status === 401 && auth && auth.enabled && path !== '/api/auth') { setSession('', null); throw new LoginRequired(); }
  if (!r.ok) throw new Error((body && body.error) || ('HTTP ' + r.status));
  return body;
}

// ---- login state. `auth` is null until the server has been asked; then {enabled, hasUsers}.
let auth = null;
let session = { token: '', user: null };
try { session.token = sessionStorage.getItem('proculus.session') || ''; } catch (e) { /* storage may be unavailable */ }
const roleLabel = (r) => { const k = 'role_' + r; return TEXTS[lang][k] || r; };
const can = (perm) => !auth || !auth.enabled || (session.user && session.user.permissions.includes(perm));
function setSession(token, user) {
  session = { token, user };
  try { if (token) sessionStorage.setItem('proculus.session', token); else sessionStorage.removeItem('proculus.session'); } catch (e) { /* ignore */ }
}
class LoginRequired extends Error {}

let controlToken = '';
try { controlToken = sessionStorage.getItem('proculus.token') || ''; } catch (e) { /* storage may be unavailable */ }

async function post(path, body) {
  const headers = authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' });
  if (controlToken && !(auth && auth.enabled)) headers['X-Proculus-Token'] = controlToken;
  const r = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body || {}) });
  let data = null;
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (r.status === 401 && auth && auth.enabled && path !== '/api/login') { setSession('', null); throw new LoginRequired(); }
  if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
  return data;
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
  const scanning = await api('/api/scan').then((s) => s.state === 'running' || s.state === 'stopping').catch(() => false);

  const changeCards = ch ? el('div', { class: 'grid' },
    stat(t('newHosts'), ch.new_hosts), stat(t('goneHosts'), ch.gone_hosts), stat(t('newServices'), ch.new_services),
    stat(t('goneServices'), ch.gone_services), stat(t('changedServices'), ch.changed_services),
    stat(t('webChanges'), ch.web_changes)) : el('p', { class: 'sub' }, t('firstRun'));

  const levelRows = d.levels.map((l) => ({ name: t(l.level), count: l.count, level: l.level }));

  return el('div', {},
    scanning ? el('div', { class: 'card', style: 'margin-bottom:14px' }, el('a', { href: '#/scan' }, t('scanInProgress') + ' →')) : null,
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


// ---- new scan: the form, the plan, and the progress of a running scan
function field(label, hint, input) {
  return el('label', { class: 'field' }, el('span', { class: 'flabel' }, label), input, hint ? el('span', { class: 'fhint' }, hint) : null);
}

function progressCard(s) {
  const cur = s.current || {};
  const pct = cur.chunks_total ? Math.round(100 * cur.chunks_done / cur.chunks_total) : 0;
  return el('div', { class: 'card', style: 'margin-bottom:14px' },
    el('h2', {}, s.state === 'stopping' ? t('stopping') : t('running')),
    el('div', { class: 'grid' },
      stat(t('stage'), cur.stage || '…'), stat(t('hostsFound'), cur.hosts_found || 0),
      stat(t('elapsed'), (cur.elapsed_seconds || 0) + t('seconds')), stat(t('pausesN'), cur.pauses || 0)),
    el('div', { class: 'bar-row', style: 'grid-template-columns:120px 1fr 90px' },
      el('span', { class: 'lbl' }, t('chunksDone')), el('div', { class: 'bar' }, el('i', { style: 'width:' + pct + '%' })), el('span', {}, (cur.chunks_done || 0) + ' / ' + (cur.chunks_total || 0))),
    el('div', { class: 'toolbar', style: 'margin-top:12px' }, el('button', { class: 'danger', disabled: s.state === 'stopping', onclick: async (e) => {
      e.target.disabled = true;
      try { await post('/api/scan/stop'); } catch (err) { alert(err.message); }
      render();
    } }, t('stop'))),
    logBox(s.log));
}

function logBox(lines) {
  return lines && lines.length ? el('div', {}, el('h2', { style: 'margin-top:12px' }, t('log')), el('pre', { class: 'log' }, lines.join('\n'))) : null;
}

function lastCard(last) {
  if (!last) return null;
  return el('div', { class: 'card', style: 'margin-bottom:14px' },
    el('h2', {}, t('lastScan') + ': ', el('span', { class: last.ok ? 'tag-new' : 'tag-gone' }, last.ok ? t('scanOk') : t('scanFailed'))),
    el('p', { class: 'sub' }, last.message + ' · ' + t('finishedAt') + ' ' + when(last.finished)),
    last.ok ? el('p', {}, t('hosts') + ': ' + last.hosts + ' · ' + t('servicesN') + ': ' + last.services + (last.web_responding ? ' · ' + t('webServices') + ': ' + last.web_responding : '') +
      ' · ' + t('detections') + ': ' + last.detections + ' · ' + t('savedAs') + ' #' + last.run_id + ' ', el('button', { onclick: () => go('services', { run: last.run_id }) }, t('openRun'))) : null,
    last.warnings && last.warnings.length ? el('div', {}, el('h2', {}, t('warnings')), el('ul', { class: 'reasons' }, last.warnings.map((w) => el('li', {}, w)))) : null);
}

async function viewScan() {
  const s = await api('/api/scan');
  if (!s.enabled) return el('div', { class: 'card empty' }, el('h2', {}, t('scanDisabled')), el('p', {}, t('scanDisabledHint')));
  const p = s.policy;
  const out = el('div', {}, el('h1', {}, t('scanTitle')),
    el('p', { class: 'sub' }, t('limits') + ': ' + t('scope') + ' ' + p.scope + ' · ' + t('allowedPorts') + ' ' + p.allowed_ports + ' · ' + t('maxWorkers') + ' ' + p.max_workers + ' · ' + t('maxRate') + ' ' + p.max_rate));

  if (s.state !== 'idle') {
    out.append(progressCard(s));
    pollScan(); // keep it fresh while this page is open
    return out;
  }
  if (s.last) out.append(lastCard(s.last));

  const targets = el('textarea', { rows: 5, placeholder: '192.168.1.0/24\nexample.org' });
  const exclusions = el('textarea', { rows: 3, placeholder: '192.168.1.1' });
  const ports = el('input', { type: 'text', placeholder: p.allowed_ports });
  const workers = el('input', { type: 'number', min: 1, max: p.max_workers, value: Math.min(2, p.max_workers) });
  const rate = el('input', { type: 'number', min: 1, max: p.max_rate, value: Math.min(100, p.max_rate) });
  const timing = el('select', {}, [0, 1, 2, 3, 4].map((n) => el('option', { value: n, selected: n === 3 }, 'T' + n)));
  const web = el('input', { type: 'checkbox', checked: p.allow_web });
  const priv = el('input', { type: 'checkbox' });
  const token = el('input', { type: 'password', autocomplete: 'off', value: controlToken, placeholder: '…' });
  const message = el('div', {});
  const planBox = el('div', {});

  const list = (box) => box.value.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
  const request = () => ({ targets: list(targets), exclusions: list(exclusions), ports: ports.value.trim(), workers: Number(workers.value), rate: Number(rate.value),
    timing: Number(timing.value), web: web.checked, privileged: priv.checked });
  const remember = () => { controlToken = token.value.trim(); try { sessionStorage.setItem('proculus.token', controlToken); } catch (e) { /* ignore */ } };
  const fail = (e) => message.replaceChildren(el('div', { class: 'err' }, e.message));

  const planBtn = el('button', { onclick: async () => {
    remember(); message.replaceChildren(); planBox.replaceChildren();
    try {
      const r = await post('/api/scan/plan', request());
      const lines = [r.addresses + ' ' + t('addresses'), r.chunks + ' ' + t('chunksN') + ' (' + r.chunk_size + ')', r.workers + ' × ' + r.rate + ' pkt/s',
        t('estimate') + ': ' + Math.round(r.discovery_estimate_seconds / 60 * 10) / 10 + ' min'];
      if (r.excluded) lines.push(r.excluded + ' ' + t('excluded'));
      if (r.domains) lines.push(r.domains + ' ' + t('domainsN'));
      planBox.replaceChildren(el('div', { class: 'card', style: 'margin-top:10px' }, el('h2', {}, t('planResult')), el('ul', { class: 'reasons' }, lines.concat(r.warnings).map((l) => el('li', {}, l)))));
    } catch (e) { fail(e); }
  } }, t('plan'));
  const startBtn = el('button', { class: 'primary', onclick: async () => {
    remember(); message.replaceChildren();
    try { await post('/api/scan', request()); render(); } catch (e) { fail(e); }
  } }, t('start'));

  out.append(el('div', { class: 'card' },
    field(t('targets'), t('targetsHint'), targets), field(t('exclusions'), t('exclusionsHint'), exclusions), field(t('ports'), t('portsHint'), ports),
    el('div', { class: 'row3' }, field(t('workers'), '', workers), field(t('rate'), '', rate), field(t('timing'), '', timing)),
    p.allow_web ? el('label', { class: 'check' }, web, ' ' + t('web')) : null,
    p.allow_privileged ? el('label', { class: 'check' }, priv, ' ' + t('privileged')) : null,
    auth && auth.enabled ? null : field(t('token'), t('tokenHint'), token),
    el('div', { class: 'toolbar' }, planBtn, startBtn), message, planBox));
  return out;
}

let scanPollToken = 0;
function pollScan() {
  const mine = ++scanPollToken;
  const tick = async () => {
    await new Promise((r) => setTimeout(r, 2000));
    if (mine !== scanPollToken || parseHash().name !== 'scan') return;
    render(); // re-reads the status; when the scan is over the form comes back
  };
  tick();
}

// ---- sign in
function viewLogin() {
  if (auth && auth.setupRequired) return viewSetup();
  const user = el('input', { type: 'text', autocomplete: 'username', autofocus: true });
  const pass = el('input', { type: 'password', autocomplete: 'current-password' });
  const message = el('div', {});
  const submit = async () => {
    message.replaceChildren();
    try {
      const r = await post('/api/login', { username: user.value.trim(), password: pass.value });
      setSession(r.token, r.user);
      location.hash = '#/dashboard';
      render();
    } catch (e) { message.replaceChildren(el('div', { class: 'err' }, e.message)); pass.value = ''; }
  };
  pass.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  user.addEventListener('keydown', (e) => { if (e.key === 'Enter') pass.focus(); });
  return el('div', { class: 'card login' }, el('h1', {}, t('login')),
    auth && !auth.hasUsers ? el('div', { class: 'err' }, el('strong', {}, t('noUsers')), ' ', t('noUsersHint')) : null,
    field(t('username'), '', user), field(t('password'), '', pass),
    el('div', { class: 'toolbar' }, el('button', { class: 'primary', onclick: submit }, t('signIn'))), message);
}

// ---- first-run setup: create the administrator (needs the setup token from the gateway console)
function viewSetup() {
  const token = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false' });
  const user = el('input', { type: 'text', autocomplete: 'username' });
  const pass = el('input', { type: 'password', autocomplete: 'new-password' });
  const again = el('input', { type: 'password', autocomplete: 'new-password' });
  const message = el('div', {});
  const submit = async () => {
    message.replaceChildren();
    if (pass.value !== again.value) { message.replaceChildren(el('div', { class: 'err' }, t('passwordsDiffer'))); return; }
    try {
      const r = await post('/api/setup', { setup_token: token.value.trim(), username: user.value.trim(), password: pass.value });
      auth = { enabled: true, hasUsers: true, setupRequired: false };
      setSession(r.token, r.user);
      location.hash = '#/dashboard';
      render();
    } catch (e) { message.replaceChildren(el('div', { class: 'err' }, e.message)); pass.value = ''; again.value = ''; }
  };
  again.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return el('div', { class: 'card login' }, el('h1', {}, t('setupTitle')), el('p', { class: 'sub' }, t('setupIntro')),
    field(t('setupToken'), t('setupTokenHint'), token), field(t('username'), '', user), field(t('password'), t('newPassword'), pass), field(t('confirmPassword'), '', again),
    el('div', { class: 'toolbar' }, el('button', { class: 'primary', onclick: submit }, t('createAdmin'))), message);
}

// ---- administration: users, roles, audit log
async function viewAdmin() {
  if (!auth || !auth.enabled) return el('div', { class: 'card empty' }, el('h2', {}, t('adminTitle')), el('p', {}, t('authOff')));
  if (!can('users.manage')) return el('div', { class: 'card empty' }, el('p', {}, t('forbidden')));
  const [users, roles, audit] = await Promise.all([api('/api/users'), api('/api/roles'), api('/api/audit?limit=100')]);
  const message = el('div', {});
  const done = async (fn) => {
    message.replaceChildren();
    try { await fn(); render(); } catch (e) { if (e instanceof LoginRequired) throw e; message.replaceChildren(el('div', { class: 'err' }, e.message)); }
  };
  const roleSelect = (value) => el('select', {}, roles.map((r) => el('option', { value: r.name, selected: r.name === value }, roleLabel(r.name))));

  const rows = users.map((u) => {
    const sel = roleSelect(u.role);
    return el('tr', {}, el('td', {}, u.username), el('td', {}, sel, ' ', el('button', { onclick: () => done(() => post('/api/users/update', { id: u.id, role: sel.value })) }, t('save'))),
      el('td', { class: u.disabled ? 'tag-gone' : 'tag-new' }, u.disabled ? t('disabled') : t('enabled')), el('td', {}, u.last_login ? when(u.last_login) : t('never')),
      el('td', {}, el('button', { onclick: () => done(() => post('/api/users/update', { id: u.id, disabled: !u.disabled })) }, u.disabled ? t('enable') : t('disable')), ' ',
        el('button', { onclick: () => { const pw = window.prompt(t('newPassword')); if (pw) done(() => post('/api/users/update', { id: u.id, password: pw })); } }, t('resetPassword'))));
  });
  const nu = el('input', { type: 'text', placeholder: t('username'), autocomplete: 'off' }), np = el('input', { type: 'password', placeholder: t('newPassword'), autocomplete: 'new-password' }), nr = roleSelect('viewer');

  const perms = el('div', { class: 'perms' });
  const checks = ['data.read', 'data.edit', 'data.create', 'data.delete', 'export', 'scan.run', 'config.manage', 'users.manage'].map((p) => {
    const box = el('input', { type: 'checkbox', value: p, checked: p === 'data.read' });
    perms.append(el('label', { class: 'check' }, box, ' ' + t('perm_' + p)));
    return box;
  });
  const rn = el('input', { type: 'text', placeholder: t('roleName'), autocomplete: 'off' }), rd = el('input', { type: 'text', placeholder: t('description'), autocomplete: 'off' });

  return el('div', {}, el('h1', {}, t('adminTitle')), message,
    el('div', { class: 'card', style: 'margin-bottom:14px' }, el('h2', {}, t('users')),
      el('table', {}, el('thead', {}, el('tr', {}, ['username', 'role', 'status', 'lastLogin', 'actions'].map((k) => el('th', {}, t(k))))), el('tbody', {}, rows)),
      el('div', { class: 'toolbar', style: 'margin-top:12px' }, nu, np, nr, el('button', { class: 'primary', onclick: () => done(() => post('/api/users', { username: nu.value.trim(), password: np.value, role: nr.value })) }, t('addUser')))),
    el('div', { class: 'card', style: 'margin-bottom:14px' }, el('h2', {}, t('roles')),
      el('table', {}, el('thead', {}, el('tr', {}, ['role', 'description', 'permissions', 'users', ''].map((k) => el('th', {}, k === 'users' ? t('users') : k ? t(k) : '')))),
        el('tbody', {}, roles.map((r) => el('tr', {}, el('td', {}, roleLabel(r.name), r.builtin ? el('span', { class: 'chip' }, t('builtin')) : null), el('td', {}, r.description),
          el('td', {}, r.permissions.map((p) => el('span', { class: 'chip' }, t('perm_' + p)))), el('td', {}, String(r.users)),
          el('td', {}, r.builtin ? null : el('button', { class: 'danger', onclick: () => done(() => post('/api/roles/delete', { name: r.name })) }, t('deleteRole'))))))),
      el('h2', { style: 'margin-top:14px' }, t('addRole')), el('div', { class: 'toolbar' }, rn, rd), perms,
      el('div', { class: 'toolbar' }, el('button', { class: 'primary', onclick: () => done(() => post('/api/roles', { name: rn.value.trim(), description: rd.value, permissions: checks.filter((b) => b.checked).map((b) => b.value) })) }, t('addRole')))),
    el('div', { class: 'card' }, el('h2', {}, t('audit')),
      el('table', {}, el('thead', {}, el('tr', {}, ['when_', 'who', 'action', 'entity', 'detail'].map((k) => el('th', {}, t(k))))),
        el('tbody', {}, audit.map((e) => el('tr', {}, el('td', { class: 'mono' }, when(e.at)), el('td', {}, e.user || '—'), el('td', {}, e.action), el('td', { class: 'mono' }, e.entity), el('td', {}, e.detail)))))));
}

// ---------------------------------------------------------------- shell
const ROUTES = { dashboard: viewDashboard, services: viewServices, runs: viewRuns, changes: viewChanges, scan: viewScan, admin: viewAdmin };
const ROUTE_PERMISSION = { dashboard: 'data.read', services: 'data.read', runs: 'data.read', changes: 'data.read', scan: 'scan.run', admin: 'users.manage' };

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
  const signedOut = auth && auth.enabled && !session.user;
  nav.replaceChildren(
    ...(signedOut ? [] : Object.keys(ROUTES).filter((n) => (n !== 'admin' || (auth && auth.enabled)) && can(ROUTE_PERMISSION[n])).map((n) => el('a', { href: '#/' + n, class: n === active ? 'active' : '' }, t(n)))),
    // a placeholder for the next step (entering data by hand and importing it)
    ...(signedOut || !can('data.create') ? [] : [el('span', { class: 'soon', title: t('soon') }, t('add'))]));
  const box = document.getElementById('userbox');
  box.replaceChildren(...(session.user ? [el('span', { class: 'who' }, session.user.username + ' · ' + roleLabel(session.user.role)),
    el('button', { onclick: async () => { try { await post('/api/logout'); } catch (e) { /* the session may be gone already */ } setSession('', null); location.hash = '#/dashboard'; render(); } }, t('signOut'))] : []));
}

let renderToken = 0;
async function render() {
  const token = ++renderToken;
  const view = document.getElementById('view');
  document.documentElement.lang = lang;
  try {
    if (!auth) auth = await fetch('/api/auth').then((r) => (r.ok ? r.json() : { enabled: false })).then((a) => ({ enabled: !!a.enabled, hasUsers: a.has_users !== false, setupRequired: !!a.setup_required })).catch(() => ({ enabled: false, hasUsers: true }));
    if (auth.enabled && session.token && !session.user) {
      try { session.user = (await api('/api/me')).user; } catch (e) { if (!(e instanceof LoginRequired)) throw e; }
    }
    const { name, params } = parseHash();
    renderNav(name);
    if (auth.enabled && !session.user) { if (token === renderToken) view.replaceChildren(viewLogin()); return; }
    if (!can(ROUTE_PERMISSION[name])) { view.replaceChildren(el('div', { class: 'card empty' }, el('p', {}, t('forbidden')))); return; }
    view.replaceChildren(el('p', { class: 'sub' }, t('loading')));
    const node = await ROUTES[name](params);
    if (token === renderToken) view.replaceChildren(...(auth.enabled ? [node] : [el('div', { class: 'err warn' }, t('openMode')), node]));
  } catch (e) {
    if (e instanceof LoginRequired) { if (token === renderToken) { renderNav('dashboard'); view.replaceChildren(viewLogin()); } return; }
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
