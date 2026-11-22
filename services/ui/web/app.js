'use strict';
// Proculus web UI. Everything shown comes from scanned networks (titles,
// banners, host names) and is untrusted: it is only ever put on the page with
// textContent / text nodes, never as HTML.

// ---------------------------------------------------------------- texts
const TEXTS = {
  pl: {
    dashboard: 'Dashboard', services: 'Usługi', runs: 'Skany', changes: 'Zmiany', add: 'Dodaj dane', admin: 'Administracja', soon: 'wkrótce',
    scan: 'Nowy skan', scanTitle: 'Nowy skan', scanDisabled: 'Uruchamianie skanów z interfejsu jest wyłączone na tym serwerze.',
    scanDisabledHint: 'Administrator włącza je w zakładce Admin → Skanowanie (zakres adresów, porty, limity).',
    limits: 'Limity ustawione przez administratora', scope: 'Zakres', allowedPorts: 'Dozwolone porty', maxWorkers: 'maks. procesów', maxRate: 'maks. pakietów/s',
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
    edit: 'Edytuj', edits: 'Edycje', editTitle: 'Edycja', editHost: 'Host', editService: 'Usługa', scanSays: 'Skan wykrył', hostnameLabel: 'Nazwa hosta', environment: 'Środowisko',
    statusLabel: 'Status', priorityLabel: 'Priorytet (0–100)', priorityHint: 'Puste = wyliczony automatycznie', tagsLabel: 'Tagi', tagsHint: 'oddzielone przecinkami', noteLabel: 'Notatka',
    saveHost: 'Zapisz hosta', saveService: 'Zapisz usługę', removeEdits: 'Usuń edycje', close: 'Zamknij', hideIgnored: 'Ukryj ignorowane', onlyEdited: 'Tylko edytowane',
    env_prod: 'produkcja', env_staging: 'staging', env_test: 'test', env_dev: 'dev', st_ignored: 'ignorowane', st_false_positive: 'fałszywy alarm', st_confirmed: 'potwierdzone', st_none: '—',
    editsHelp: 'Edycje są zapisywane osobno od skanów: kolejne skany ich nie nadpiszą. Pozostają też wtedy, gdy host chwilowo nie odpowiada.', noEdits: 'Nie ma jeszcze żadnych edycji.',
    editedBy: 'Edytował', editedAt: 'Kiedy', scanValue: 'skan', savedEdit: 'Zapisano edycję.', target: 'Obiekt',
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
    scanDisabledHint: 'An administrator turns it on in the Admin tab → Scanning (address scope, ports, limits).',
    limits: 'Limits set by an administrator', scope: 'Scope', allowedPorts: 'Allowed ports', maxWorkers: 'max processes', maxRate: 'max packets/s',
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
    edit: 'Edit', edits: 'Edits', editTitle: 'Edit', editHost: 'Host', editService: 'Service', scanSays: 'The scan found', hostnameLabel: 'Host name', environment: 'Environment',
    statusLabel: 'Status', priorityLabel: 'Priority (0-100)', priorityHint: 'Empty = computed automatically', tagsLabel: 'Tags', tagsHint: 'separated by commas', noteLabel: 'Note',
    saveHost: 'Save host', saveService: 'Save service', removeEdits: 'Remove edits', close: 'Close', hideIgnored: 'Hide ignored', onlyEdited: 'Only edited',
    env_prod: 'production', env_staging: 'staging', env_test: 'test', env_dev: 'dev', st_ignored: 'ignored', st_false_positive: 'false positive', st_confirmed: 'confirmed', st_none: '—',
    editsHelp: 'Edits are kept apart from the scans, so later scans never overwrite them. They also stay when a host does not answer for a while.', noEdits: 'There are no edits yet.',
    editedBy: 'Edited by', editedAt: 'When', scanValue: 'scan', savedEdit: 'Edit saved.', target: 'Object',
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


// ---- texts added for the new layout (Polish first, as in the Python build)
Object.assign(TEXTS.pl, {
  presetLabel: 'Gotowy zestaw', presetNone: '— własne ustawienia —', presetHint: 'Wypełnia formularz; możesz go dalej zmienić. Co wolno skanować, i tak ustala administrator.', presetBuiltin: 'Wbudowane', presetMine: 'Moje zestawy',
  presetSave: 'Zapisz jako zestaw', presetSaveAsk: 'Nazwa zestawu (zapisywany w tej przeglądarce):', presetDelete: 'Usuń zestaw', presetSaved: 'Zapisano zestaw', presetNeedTargets: 'Wpisz najpierw cele skanu.',
  presetAddTo: 'Dodaj do zakresu i portów z zestawu:',
  scanCfgTitle: 'Skanowanie (ustawienia administratora)', scanCfgIntro: 'Skany z interfejsu są wyłączone, dopóki ich tu nie włączysz. Formularz „Nowy skan” może wybrać tylko cele z zakresu i porty z listy poniżej.',
  scanCfgEnabled: 'Skanowanie z interfejsu włączone', scanCfgScope: 'Zakres adresów', scanCfgScopeHint: 'IP, CIDR lub zakresy, po przecinku, np. 10.250.165.0/24', scanCfgPorts: 'Dozwolone porty', scanCfgPortsHint: 'np. 22,80,443,8000-8100',
  scanCfgWorkers: 'Maks. procesów nmap', scanCfgRate: 'Maks. pakietów/s na proces', scanCfgWeb: 'Zezwól na sondowanie WWW', scanCfgPriv: 'Zezwól na skany surowymi gniazdami (wymaga uprawnień)', scanCfgReserved: 'Zezwól na adresy zarezerwowane (loopback itp.; tylko lokalne laboratorium)',
  scanCfgCeiling: 'Twardy limit operatora (--scan-ceiling)', scanCfgNoCeiling: 'brak', scanCfgSave: 'Zapisz ustawienia skanowania', scanCfgSaved: 'Zapisano.',
  tab_dashboard: '1. Dashboard & Skaner', tab_results: '2. Wyniki & Edycja', tab_changes: '3. Zmiany w czasie (Diff)', tab_targets: '4. Cele (CSV / JSON)',
  tab_signatures: '5. Własne sygnatury', tab_schedule: '6. Harmonogram & DefectDojo', tab_admin: '7. Administracja RBAC',
  brandSub: 'ATTACK SURFACE INTELLIGENCE', badgeAuthOn: 'LOGOWANIE WŁĄCZONE', badgeAuthOff: 'BEZ LOGOWANIA', badgeScope: 'Zakres skanu', tourBtn: 'Przewodnik', account: 'Konto',
  kpiHosts: 'Aktywne hosty', kpiServices: 'Wykryte usługi', kpiInteresting: 'Panele admina / staging', kpiUnstable: 'Hosty niestabilne',
  tipHosts: 'Liczba unikalnych adresów IP z ostatniego skanu, które odpowiedziały na co najmniej jeden port lub usługę.',
  tipServices: 'Suma otwartych portów i zidentyfikowanych usług w ostatnim skanie. Zielony/czerwony wskaźnik pokazuje zmianę względem poprzedniego skanu.',
  tipInteresting: 'Usługi dopasowane do sygnatur typu panel administracyjny lub środowisko testowe/staging (wymagają dalszej analizy).',
  tipUnstable: 'Hosty, które odpowiadają nieregularnie (niestabilne) lub przestały odpowiadać (nieaktywne). Wynik na podstawie historii wszystkich skanów.',
  cfgTitle: 'Konfiguracja skanowania', telemetryTitle: 'Telemetria skanowania na żywo', scanUnavailable: 'Skanowanie z interfejsu jest niedostępne',
  scanForbidden: 'Twoja rola nie ma uprawnienia do uruchamiania skanów (scan.run).',
  st1: 'Discovery', st1s: 'Wykrywanie hostów', st2: 'Usługi (nmap)', st2s: 'Porty i wersje', st3: 'HTTP / TLS', st3s: 'Nagłówki, CMS, TLS', st4: 'Sygnatury', st4s: 'Dopasowanie i zapis',
  liveEmpty: 'Po uruchomieniu skanowania tutaj pojawią się na żywo hosty, które odpowiedziały, i porty znalezione na nich.', liveIdle: 'CEL: oczekiwanie na uruchomienie',
  stageIdle: 'ETAP: IDLE', stagePrefix: 'ETAP', scanPrefix: 'SKAN', doneNow: 'ZAKOŃCZONO', ready: 'Gotowy do skanowania', hostsShort: 'Hosty', chunkShort: 'Porcja', timeShort: 'Czas',
  pausesShort: 'Pauzy', noOpen: 'brak otwartych', answering: 'ODPOWIADA', probing: 'SKANOWANY',
  summaryTitle: 'Podsumowanie ostatniego skanu', saveTxt: 'Zapisz raport TXT', noSummary: 'Brak zapisanych skanów. Uruchom skan powyżej albo wczytaj dane, aby zobaczyć podsumowanie.',
  tipSaveTxt: 'Pobiera podsumowanie ostatniego skanu jako plik tekstowy (.txt).',
  stabilityTitle: 'Monitor stabilności hostów (okresowa dostępność w czasie)', stateCol: 'Stan', sightingsCol: 'Wykrycia', lastRunCol: 'Ostatni skan', allStable: 'Wszystkie hosty odpowiadają stabilnie.',
  resultsTitle: 'Wykryte usługi i artefakty', sub_services: 'Usługi', sub_runs: 'Skany', sub_edits: 'Edycje',
  soonTitle: 'W przygotowaniu', soonTargets: 'Wczytywanie celów skanowania i wyników z plików CSV / JSON oraz ręczne wprowadzanie danych (formularz). Dane trafią do tego samego potoku co skany: sygnatury, porównania, dashboard.',
  soonSignatures: 'Przeglądanie wbudowanych sygnatur i tworzenie własnych (format JSON, walidacja i testy przykładów). Na razie sygnatury dodaje się z linii poleceń: signatures lint / http-prober --signatures.',
  soonSchedule: 'Harmonogram cyklicznych skanów (okno czasowe, częstotliwość) i eksport obserwacji do DefectDojo. Na razie: runner --window --interval oraz scheduler.',
  gateSub: 'Attack Surface Intelligence', gateBadge: 'Sesja z tokenem • role RBAC', loginBtn: 'Zaloguj do konsoli Proculus', setupSub: 'Inicjalizacja • pierwsze uruchomienie',
  tourTitle: 'PROCULUS — Przewodnik', tourStep: 'Krok', tourOf: 'z', tourSkip: 'Pomiń', tourPrev: '◀ Wstecz', tourNext: 'Dalej ▶', tourFinish: 'Zakończ ✔',
  tour1: 'To cztery główne wskaźniki ostatniego skanu: aktywne hosty, wykryte usługi, panele admina / staging i hosty niestabilne. Najedź kursorem na kartę, aby zobaczyć objaśnienie.',
  tour2: 'Tutaj konfigurujesz skan: cele, wyłączenia, porty, liczbę procesów, tempo i sondowanie web. Operator ustawia twarde limity: formularz może tylko mieścić się w nich.',
  tour3: '„Pokaż plan” oblicza liczbę adresów, porcji i szacowany czas bez wysyłania żadnych pakietów. „Uruchom skan” startuje skanowanie.',
  tour4: 'Telemetria na żywo: cztery etapy, hosty które właśnie odpowiedziały wraz z otwartymi portami, pasek postępu i dziennik zdarzeń.',
  tour5: 'Po skanie znajdziesz tu podsumowanie, które możesz zapisać jako plik .TXT, a poniżej najważniejsze znaleziska i zmiany względem poprzedniego skanu.',
  tipTargets: 'Adresy IP, zakresy CIDR (np. 192.168.1.0/24), zakresy (10.0.0.1-10.0.0.50) lub domeny. Wszystko musi mieścić się w zakresie dozwolonym przez operatora.',
  tipWorkers: 'Ile procesów nmap działa równolegle. Łączne tempo = procesy × pakiety/s na proces.', tipRate: 'Maksymalna liczba pakietów na sekundę na jeden proces nmap. Niższa wartość jest ostrożniejsza dla sieci.',
  tipTiming: 'Poziom -T nmap: 0 najwolniejszy i najcichszy, 4 najszybszy. 3 jest zalecane.', tipWeb: 'Po wykryciu usług webowych pobiera stronę główną (GET), nagłówki, ciasteczka, certyfikat TLS i dopasowuje sygnatury technologii.',
  viewServices: 'Pokaż usługi', tipPlan: 'Oblicza plan skanu (adresy, porcje, szacowany czas) bez wysyłania pakietów.', tipStart: 'Uruchamia skan z podanymi ustawieniami. W jednej chwili może działać tylko jeden skan.', tipStop: 'Bezpiecznie przerywa skan. Niepełny skan nie jest zapisywany.',
  scanRunning: 'W toku', scanStopped: 'Zatrzymany', finishedOk: 'Zakończony',
});
Object.assign(TEXTS.en, {
  presetLabel: 'Preset', presetNone: '— custom settings —', presetHint: 'Fills in the form; you can still change it. What may be scanned is decided by the administrator anyway.', presetBuiltin: 'Built in', presetMine: 'My presets',
  presetSave: 'Save to preset', presetSaveAsk: 'Preset name (kept in this browser):', presetDelete: 'Delete preset', presetSaved: 'Preset saved', presetNeedTargets: 'Enter the scan targets first.',
  presetAddTo: 'Add to the scope and ports from a preset:',
  scanCfgTitle: 'Scanning (administrator settings)', scanCfgIntro: 'Scans from the UI stay off until you turn them on here. The "New scan" form can only pick targets inside the scope and ports from the list below.',
  scanCfgEnabled: 'Scanning from the UI enabled', scanCfgScope: 'Address scope', scanCfgScopeHint: 'IPs, CIDRs or ranges, comma separated, e.g. 10.250.165.0/24', scanCfgPorts: 'Allowed ports', scanCfgPortsHint: 'e.g. 22,80,443,8000-8100',
  scanCfgWorkers: 'Max nmap processes', scanCfgRate: 'Max packets/s per process', scanCfgWeb: 'Allow web probing', scanCfgPriv: 'Allow raw-socket scans (needs privileges)', scanCfgReserved: 'Allow reserved addresses (loopback etc.; local lab only)',
  scanCfgCeiling: "Operator's hard limit (--scan-ceiling)", scanCfgNoCeiling: 'none', scanCfgSave: 'Save scan settings', scanCfgSaved: 'Saved.',
  tab_dashboard: '1. Dashboard & Scanner', tab_results: '2. Results & Edit', tab_changes: '3. Changes over time (Diff)', tab_targets: '4. Targets (CSV / JSON)',
  tab_signatures: '5. Custom signatures', tab_schedule: '6. Schedule & DefectDojo', tab_admin: '7. Administration (RBAC)',
  brandSub: 'ATTACK SURFACE INTELLIGENCE', badgeAuthOn: 'LOGIN ON', badgeAuthOff: 'NO LOGIN', badgeScope: 'Scan scope', tourBtn: 'Guide', account: 'Account',
  kpiHosts: 'Active hosts', kpiServices: 'Detected services', kpiInteresting: 'Admin panels / staging', kpiUnstable: 'Unstable hosts',
  tipHosts: 'Unique IP addresses of the latest scan that answered on at least one port or service.',
  tipServices: 'Open ports and identified services in the latest scan. The green/red figure is the change against the previous scan.',
  tipInteresting: 'Services matching admin panel or test/staging signatures (worth a closer look).',
  tipUnstable: 'Hosts that answer irregularly (unstable) or stopped answering (stale), judged from the history of all scans.',
  cfgTitle: 'Scan configuration', telemetryTitle: 'Live scan telemetry', scanUnavailable: 'Starting scans from the UI is not available',
  scanForbidden: 'Your role is not allowed to start scans (scan.run).',
  st1: 'Discovery', st1s: 'Finding hosts', st2: 'Services (nmap)', st2s: 'Ports and versions', st3: 'HTTP / TLS', st3s: 'Headers, CMS, TLS', st4: 'Signatures', st4s: 'Matching and saving',
  liveEmpty: 'Once a scan starts, the hosts that answered and the ports found on them appear here live.', liveIdle: 'TARGET: waiting to start',
  stageIdle: 'STAGE: IDLE', stagePrefix: 'STAGE', scanPrefix: 'SCAN', doneNow: 'FINISHED', ready: 'Ready to scan', hostsShort: 'Hosts', chunkShort: 'Chunk', timeShort: 'Time',
  pausesShort: 'Pauses', noOpen: 'no open ports', answering: 'ANSWERING', probing: 'SCANNING',
  summaryTitle: 'Summary of the latest scan', saveTxt: 'Save TXT report', noSummary: 'No saved scans yet. Start a scan above or load data to see a summary.',
  tipSaveTxt: 'Downloads the summary of the latest scan as a text file (.txt).',
  stabilityTitle: 'Host stability monitor (availability over time)', stateCol: 'State', sightingsCol: 'Sightings', lastRunCol: 'Last run', allStable: 'All hosts answer reliably.',
  resultsTitle: 'Detected services and artefacts', sub_services: 'Services', sub_runs: 'Runs', sub_edits: 'Edits',
  soonTitle: 'Coming soon', soonTargets: 'Loading scan targets and results from CSV / JSON files, and entering data by hand (a form). The data will go through the same pipeline as scans: signatures, comparison, dashboard.',
  soonSignatures: 'Browsing the built-in signatures and writing your own (JSON format, validation and example tests). For now signatures are added from the command line: signatures lint / http-prober --signatures.',
  soonSchedule: 'A schedule of recurring scans (time window, frequency) and exporting observations to DefectDojo. For now: runner --window --interval, and the scheduler.',
  gateSub: 'Attack Surface Intelligence', gateBadge: 'Token sessions • RBAC roles', loginBtn: 'Sign in to the Proculus console', setupSub: 'Initialisation • first run',
  tourTitle: 'PROCULUS — Guide', tourStep: 'Step', tourOf: 'of', tourSkip: 'Skip', tourPrev: '◀ Back', tourNext: 'Next ▶', tourFinish: 'Finish ✔',
  tour1: 'The four main figures of the latest scan: active hosts, detected services, admin panels / staging and unstable hosts. Hover a card for an explanation.',
  tour2: 'Configure a scan here: targets, exclusions, ports, processes, rate and web probing. The operator sets hard limits; the form can only stay within them.',
  tour3: '"Show plan" works out the addresses, chunks and estimated time without sending any packets. "Start scan" begins the scan.',
  tour4: 'Live telemetry: the four stages, the hosts that just answered with their open ports, a progress bar and the event log.',
  tour5: 'After a scan you get a summary here that you can save as a .TXT file, with the top findings and the changes against the previous scan below.',
  tipTargets: 'IP addresses, CIDR ranges (e.g. 192.168.1.0/24), ranges (10.0.0.1-10.0.0.50) or domains. Everything must lie inside the scope the operator allows.',
  tipWorkers: 'How many nmap processes run in parallel. Total rate = processes × packets/s per process.', tipRate: 'Maximum packets per second for one nmap process. Lower is gentler on the network.',
  tipTiming: 'nmap -T level: 0 is slowest and quietest, 4 fastest. 3 is recommended.', tipWeb: 'After finding web services, fetches the home page (GET), headers, cookies and the TLS certificate and matches technology signatures.',
  viewServices: 'View services', tipPlan: 'Works out the scan plan (addresses, chunks, estimated time) without sending packets.', tipStart: 'Starts a scan with these settings. Only one scan can run at a time.', tipStop: 'Safely stops the scan. An unfinished scan is not saved.',
  scanRunning: 'Running', scanStopped: 'Stopped', finishedOk: 'Finished',
});

let lang = 'pl';
try { const saved = localStorage.getItem('proculus.lang'); if (saved === 'pl' || saved === 'en') lang = saved; } catch (e) { /* storage may be unavailable */ }
const t = (k) => (TEXTS[lang] && TEXTS[lang][k]) || (TEXTS.pl && TEXTS.pl[k]) || k;

// ---------------------------------------------------------------- helpers
const SVGNS = 'http://www.w3.org/2000/svg';
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k === 'style') e.style.cssText = v; // through the CSSOM: the Content-Security-Policy blocks style attributes
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === undefined || kid === null || kid === false) continue;
    e.appendChild(typeof kid === 'object' ? kid : document.createTextNode(String(kid)));
  }
  return e;
}
const $ = (sel) => document.querySelector(sel);

// the emblem is defined once in index.html and referenced from here
function emblem(size) {
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 100 100');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVGNS, 'use');
  use.setAttribute('href', '#proculus-emblem');
  svg.appendChild(use);
  return svg;
}

// ---- login state. `auth` is null until the server has been asked; then {enabled, hasUsers, setupRequired}.
let auth = null;
let session = { token: '', user: null };
try { session.token = sessionStorage.getItem('proculus.session') || ''; } catch (e) { /* storage may be unavailable */ }
const roleLabel = (r) => TEXTS[lang]['role_' + r] || r;
const can = (perm) => !auth || !auth.enabled || (session.user && session.user.permissions.includes(perm));
function setSession(token, user) {
  session = { token, user };
  try { if (token) sessionStorage.setItem('proculus.session', token); else sessionStorage.removeItem('proculus.session'); } catch (e) { /* ignore */ }
}
class LoginRequired extends Error {}

let controlToken = '';
try { controlToken = sessionStorage.getItem('proculus.token') || ''; } catch (e) { /* ignore */ }

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

async function post(path, body) {
  const headers = authHeaders({ 'Content-Type': 'application/json', Accept: 'application/json' });
  if (controlToken && !(auth && auth.enabled)) headers['X-Proculus-Token'] = controlToken;
  const r = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body || {}) });
  let data = null;
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (r.status === 401 && auth && auth.enabled && path !== '/api/login' && path !== '/api/setup') { setSession('', null); throw new LoginRequired(); }
  if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
  return data;
}

const qs = (o) => Object.entries(o).filter(([, v]) => v !== '' && v !== undefined && v !== null).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
const when = (iso) => (iso || '').replace('T', ' ').replace(/:\d\dZ$/, 'Z');
const go = (route, params) => { location.hash = '#/' + route + (params && qs(params) ? '?' + qs(params) : ''); };
const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function score(n, level) { return el('span', { class: 'score ' + level, title: t(level) }, String(n)); }

// a card heading with an optional tooltip; `tip` is read by the global tooltip handler
function tip(title, text, node) { node.setAttribute('data-tip-title', title); node.setAttribute('data-tip', text); return node; }

function kpi(label, value, cls, delta, tipText) {
  const card = el('div', { class: 'card' }, el('h3', {}, label), el('div', { class: 'kpi-val ' + (cls || '') }, String(value)), delta || null);
  return tipText ? tip(label, tipText, card) : card;
}
const deltaNote = (n) => el('div', { class: 'kpi-note ' + (n === 0 ? 'flat' : n > 0 ? 'up' : 'down') }, (n > 0 ? '+' : '') + n);

function bars(rows, nameOf, level) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return rows.length ? rows.map((r) => el('div', { class: 'bar-row' },
    el('span', { class: 'lbl', title: nameOf(r) }, nameOf(r)),
    el('div', { class: 'bar ' + (level ? level(r) : '') }, el('i', { style: 'width:' + Math.round(100 * r.count / max) + '%' })),
    el('span', {}, String(r.count)))) : el('p', { class: 'sub' }, '—');
}

function field(label, hint, input, tipText) {
  return el('label', { class: 'field' }, el('span', { class: 'flabel' }, label, tipText ? tip(label, tipText, el('span', { class: 'hint-icon' }, '?')) : null), input, hint ? el('span', { class: 'fhint' }, hint) : null);
}

// ---------------------------------------------------------------- tooltip (one element, positioned when shown)
const tooltipEl = $('#hoverTooltip');
let tipTarget = null;
function placeTip(x, y) {
  const w = tooltipEl.offsetWidth, h = tooltipEl.offsetHeight;
  let left = x + 16, top = y + 16;
  if (left + w > window.innerWidth - 8) left = x - w - 12;
  if (top + h > window.innerHeight - 8) top = y - h - 12;
  tooltipEl.style.left = Math.max(8, left) + 'px';
  tooltipEl.style.top = Math.max(8, top) + 'px';
}
function hideTip() { tipTarget = null; tooltipEl.classList.remove('show'); }
document.addEventListener('mouseover', (e) => {
  const target = e.target.closest ? e.target.closest('[data-tip]') : null;
  if (target === tipTarget) return;
  if (!target) { hideTip(); return; }
  tipTarget = target;
  tooltipEl.replaceChildren(el('b', {}, target.getAttribute('data-tip-title') || ''), target.getAttribute('data-tip'));
  placeTip(e.clientX, e.clientY); // placed before it is shown, so it never appears at the previous position
  tooltipEl.classList.add('show');
});
document.addEventListener('mousemove', (e) => { if (tipTarget) placeTip(e.clientX, e.clientY); });
document.addEventListener('mouseout', (e) => { if (!e.relatedTarget) hideTip(); });
document.addEventListener('scroll', hideTip, true);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideTip(); });

// ---------------------------------------------------------------- services table and the edit dialog
function serviceRow(f, onclick) {
  const tags = [...((f.edit && f.edit.host && f.edit.host.tags) || []), ...((f.edit && f.edit.service && f.edit.service.tags) || [])];
  const env = f.edit && f.edit.host && f.edit.host.environment;
  const notes = [f.edit && f.edit.host && f.edit.host.note, f.edit && f.edit.service && f.edit.service.note].filter(Boolean).join('\n');
  return el('tr', onclick ? { class: 'click', onclick } : {},
    el('td', {}, score(f.score, f.level)),
    el('td', { class: 'mono' }, f.ip + ':' + f.port + '/' + f.protocol),
    el('td', {}, f.hostname, f.scan_hostname !== undefined ? el('div', { class: 'scanval' }, t('scanValue') + ': ' + (f.scan_hostname || '—')) : null),
    el('td', {}, f.service),
    el('td', {}, f.title),
    el('td', {}, f.status ? el('span', { class: 'chip st-' + f.status }, t('st_' + f.status)) : null, env ? el('span', { class: 'chip' }, t('env_' + env)) : null,
      tags.map((x) => el('span', { class: 'chip' }, '#' + x)), f.detections.map((d) => el('span', { class: 'chip' }, d)), notes ? el('div', { class: 'note', title: notes }, '✎ ' + notes) : null),
    el('td', {}, f.reasons.length ? el('ul', { class: 'reasons' }, f.reasons.map((r) => el('li', {}, r))) : ''),
    can('data.edit') ? el('td', {}, el('button', { class: 'sec', onclick: (e) => { e.stopPropagation(); openEdit(f); } }, t('edit'))) : null);
}

function servicesHead() {
  return el('thead', {}, el('tr', {}, ['score', 'address', 'hostname', 'service', 'title', 'found', 'why'].map((k) => el('th', {}, t(k))), can('data.edit') ? el('th', {}, '') : null));
}

function openEdit(f) {
  const old = $('#editModal');
  if (old) old.remove();
  const hostEdit = (f.edit && f.edit.host) || {}, svcEdit = (f.edit && f.edit.service) || {};
  const message = el('div', {});
  const token = el('input', { type: 'password', autocomplete: 'off', value: controlToken, placeholder: '…' });
  const close = () => { const m = $('#editModal'); if (m) m.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  const sel = (options, value, labelOf) => el('select', {}, el('option', { value: '' }, t('st_none')), options.map((o) => el('option', { value: o, selected: o === value }, labelOf(o))));
  const textRow = (value) => el('input', { type: 'text', value: value || '' });

  function section(title, existing, isHost) {
    const hostname = isHost ? textRow(existing.hostname) : null;
    const environment = isHost ? sel(['prod', 'staging', 'test', 'dev'], existing.environment, (o) => t('env_' + o)) : null;
    const status = sel(['ignored', 'false_positive', 'confirmed'], existing.status, (o) => t('st_' + o));
    const priority = el('input', { type: 'number', min: 0, max: 100, value: existing.priority !== undefined ? existing.priority : '' });
    const tags = textRow((existing.tags || []).join(', '));
    const note = el('textarea', { rows: 3 });
    note.value = existing.note || '';
    const key = isHost ? { ip: f.ip } : { ip: f.ip, port: f.port, protocol: f.protocol };
    const payload = () => {
      const changes = { status: status.value || null, priority: priority.value === '' ? null : Number(priority.value), tags: tags.value.split(',').map((x) => x.trim()).filter(Boolean), note: note.value || null };
      if (isHost) { changes.hostname = hostname.value.trim() || null; changes.environment = environment.value || null; }
      return Object.assign({}, key, { changes });
    };
    const remember = () => { controlToken = token.value.trim(); try { sessionStorage.setItem('proculus.token', controlToken); } catch (e) { /* ignore */ } };
    const run = async (fn) => { remember(); message.replaceChildren(); try { await fn(); close(); render(); } catch (e) { if (e instanceof LoginRequired) throw e; message.replaceChildren(el('div', { class: 'err' }, e.message)); } };
    return el('fieldset', { class: 'editbox' }, el('legend', {}, title),
      isHost ? field(t('hostnameLabel'), t('scanValue') + ': ' + (f.scan_hostname !== undefined ? (f.scan_hostname || '—') : (f.hostname || '—')), hostname) : null,
      isHost ? field(t('environment'), '', environment) : null,
      el('div', { class: 'row3' }, field(t('statusLabel'), '', status), field(t('priorityLabel'), t('priorityHint'), priority), field(t('tagsLabel'), t('tagsHint'), tags)),
      field(t('noteLabel'), '', note),
      el('div', { class: 'toolbar' }, el('button', { onclick: () => run(() => post('/api/edits', payload())) }, isHost ? t('saveHost') : t('saveService')),
        Object.keys(existing).length ? el('button', { class: 'danger', onclick: () => run(() => post('/api/edits/clear', key)) }, t('removeEdits')) : null));
  }

  const dialog = el('div', { class: 'modal', role: 'dialog' },
    el('h1', {}, t('editTitle') + ': ' + f.ip + ':' + f.port + '/' + f.protocol),
    el('p', { class: 'sub' }, t('scanSays') + ': ' + (f.service || '—') + (f.title ? ' · ' + f.title : '')),
    section(t('editHost') + ' ' + f.ip, hostEdit, true), section(t('editService') + ' ' + f.port + '/' + f.protocol, svcEdit, false),
    auth && auth.enabled ? null : field(t('token'), t('tokenHint'), token), message,
    el('div', { class: 'toolbar' }, el('button', { class: 'sec', onclick: close }, t('close'))));
  document.body.append(el('div', { id: 'editModal', class: 'modal-bg', onclick: (e) => { if (e.target.id === 'editModal') close(); } }, dialog));
}

// ---------------------------------------------------------------- live scan: monitor, telemetry, form
let monitorTimer = null;
function stopMonitor() { if (monitorTimer) { clearInterval(monitorTimer); monitorTimer = null; } }
// polls the scan status once a second while the dashboard is open; paused while the page is hidden
function startMonitor(initial, onStatus) {
  stopMonitor();
  let busy = false, last = initial;
  const tick = async () => {
    if (busy || document.hidden) return;
    busy = true;
    try { const s = await api('/api/scan'); const prev = last; last = s; onStatus(s, prev); } catch (e) { if (e instanceof LoginRequired) { stopMonitor(); render(); } } finally { busy = false; }
  };
  monitorTimer = setInterval(tick, 1000);
  return tick;
}

const stageIndex = (stage) => ({ discovery: 1, services: 2, web: 3, saving: 4, done: 4 }[stage] || 0);

// The panel is built once and updated in place: rows, chips and log lines are added or changed, never rebuilt,
// so nothing flickers and the log keeps its scroll position unless it is already at the bottom.
function buildTelemetry() {
  const pills = [1, 2, 3, 4].map((i) => el('div', { class: 'stage-pill' }, el('b', {}, i + '. ' + t('st' + i)), t('st' + i + 's')));
  const dot = el('span', { class: 'pulse-dot' });
  const target = el('b', {}, t('liveIdle'));
  const stageLabel = el('span', { style: 'color:var(--accent);font-weight:700' }, t('stageIdle'));
  const empty = el('div', { class: 'live-empty' }, t('liveEmpty'));
  const list = el('div', { class: 'live-host-list' }, empty);
  const bar = el('div', { class: 'prog-bar' });
  const status = el('span', { style: 'font-weight:700;color:var(--accent)' }, t('ready'));
  const numbers = el('span', { class: 'mono' }, '0%');
  const vHosts = el('b', {}, '0'), vChunk = el('b', {}, '0/0'), vTime = el('b', {}, '0s'), vPauses = el('b', {}, '0');
  const logBox = el('div', { class: 'log-box mono' });
  const stopBtn = tip(t('stop'), t('tipStop'), el('button', { class: 'danger', disabled: true }, t('stop')));
  const rows = new Map(); // ip -> { row, key, head, chips }
  let rendered = 0;

  const node = el('div', { class: 'card', id: 'tour-telemetry' },
    el('div', { class: 'toolbar', style: 'justify-content:space-between;margin-bottom:6px' }, el('h3', { style: 'margin:0' }, t('telemetryTitle')), stopBtn),
    el('div', { class: 'stages-bar' }, pills),
    el('div', { class: 'live-monitor-panel' }, el('div', { class: 'live-monitor-header mono' }, el('span', {}, dot, target), stageLabel), list),
    el('div', { style: 'display:flex;justify-content:space-between;font-size:13px' }, status, numbers),
    el('div', { class: 'prog-wrap' }, bar),
    el('div', { class: 'prog-stats' }, el('span', {}, t('hostsShort') + ': ', vHosts), el('span', {}, t('chunkShort') + ': ', vChunk), el('span', {}, t('timeShort') + ': ', vTime), el('span', {}, t('pausesShort') + ': ', vPauses)),
    logBox);

  function setHosts(visible, running, stage) {
    const keep = new Set(visible.map((h) => h.ip));
    for (const [ip, r] of rows) if (!keep.has(ip)) { r.row.remove(); rows.delete(ip); }
    visible.forEach((h, i) => {
      const isLast = i === visible.length - 1 && running && (stage === 'discovery' || stage === 'services');
      let r = rows.get(h.ip);
      if (!r) {
        r = { row: el('div', { class: 'live-host-row' }), key: null, shown: [], head: el('div', { style: 'display:flex;align-items:center;gap:8px' }), chips: el('div', { class: 'port-chips' }) };
        r.row.append(r.head, r.chips);
        rows.set(h.ip, r);
        list.append(r.row);
      }
      const key = h.ports.join(',') + '|' + isLast;
      if (r.key !== key) { // only rows whose content changed are touched
        r.key = key;
        r.head.replaceChildren(el('b', { class: 'mono', style: 'font-size:12.5px' }, h.ip),
          el('span', { class: 'badge ' + (isLast ? 'b-blue' : h.ports.length ? 'b-green' : 'b-gray') }, isLast ? t('probing') : h.ports.length ? t('answering') + ' (' + h.ports.length + ')' : t('noOpen')));
        const chips = h.ports.length ? h.ports.map((p) => el('span', { class: 'p-chip' }, String(p))) : [el('span', { class: 'p-chip none' }, '—')];
        chips.forEach((c, k) => { if (r.shown.includes(h.ports[k])) c.style.animation = 'none'; }); // ports already shown are not animated again
        r.shown = h.ports.slice();
        r.chips.replaceChildren(...chips);
        r.row.classList.toggle('online-host', h.ports.length > 0 && !isLast);
        r.row.classList.toggle('active-host', isLast);
      }
    });
    empty.hidden = visible.length > 0;
  }

  function setLog(s) {
    const lines = s.log || [], total = s.log_total !== undefined ? s.log_total : lines.length;
    const atBottom = logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight < 24;
    const fresh = total - rendered;
    if (rendered === 0 || fresh < 0 || fresh > lines.length) logBox.replaceChildren(...lines.map((l) => el('div', {}, l))); // first time, or lines were missed
    else if (fresh > 0) logBox.append(...lines.slice(lines.length - fresh).map((l) => el('div', {}, l)));
    const first = rendered === 0;
    rendered = total;
    if (atBottom || first) logBox.scrollTop = logBox.scrollHeight;
  }

  function update(s) {
    const running = s.state === 'running' || s.state === 'stopping';
    const cur = s.current || {};
    const idx = running ? stageIndex(cur.stage) : 0;
    const finishedOk = !running && s.last && s.last.ok;
    pills.forEach((p, i) => {
      p.classList.toggle('done', !!finishedOk || (running && i + 1 < idx));
      p.classList.toggle('active', running && i + 1 === idx);
    });
    dot.classList.toggle('live', running);
    target.textContent = running ? t('scanPrefix') + ': ' + (cur.stage || '…') : finishedOk ? t('doneNow') + ': ' + s.last.message : t('liveIdle');
    stageLabel.textContent = running ? t('stagePrefix') + ': ' + (cur.stage || '…').toUpperCase() : t('stageIdle');
    let pct = finishedOk ? 100 : 0;
    if (running) {
      const frac = cur.chunks_total ? Math.min(1, cur.chunks_done / cur.chunks_total) : 0;
      const base = [0, 0, 0.35, 0.75, 0.92][idx] || 0, next = [0, 0.35, 0.75, 0.92, 1][idx] || 0;
      pct = 100 * (base + (idx === 3 ? 0.5 : frac) * (next - base));
    }
    bar.style.width = pct.toFixed(1) + '%';
    bar.classList.toggle('running', running);
    status.textContent = running ? (s.state === 'stopping' ? t('stopping') : t('running')) : (s.last ? (s.last.ok ? t('finishedOk') : t('scanFailed')) : t('ready'));
    numbers.textContent = pct.toFixed(0) + '%';
    vHosts.textContent = String(cur.hosts_found || 0);
    vChunk.textContent = (cur.chunks_done || 0) + '/' + (cur.chunks_total || 0);
    vTime.textContent = (cur.elapsed_seconds || 0) + 's';
    vPauses.textContent = String(cur.pauses || 0);
    stopBtn.disabled = s.state !== 'running';
    setHosts((cur.recent_hosts || []).slice(-4), running, cur.stage);
    setLog(s);
  }
  return { node, update, stopBtn };
}

// The user's own presets live in this browser (they only fill in the form; the server decides what may be scanned).
const presetKey = () => 'proculus.presets.' + (session.user ? session.user.username : '');
function userPresets() {
  try { const v = JSON.parse(localStorage.getItem(presetKey()) || '[]'); return Array.isArray(v) ? v.filter((p) => p && typeof p.name === 'string' && Array.isArray(p.targets)) : []; } catch (e) { return []; }
}
function storeUserPresets(list) { try { localStorage.setItem(presetKey(), JSON.stringify(list.slice(0, 50))); } catch (e) { /* ignore */ } }

function scanFormCard(s, onStarted) {
  if (!s.enabled) return el('div', { class: 'card', id: 'tour-config' }, el('h3', {}, t('cfgTitle')), el('div', { class: 'empty' }, el('b', {}, t('scanUnavailable')), el('p', {}, t('scanDisabledHint'))));
  if (!can('scan.run')) return el('div', { class: 'card', id: 'tour-config' }, el('h3', {}, t('cfgTitle')), el('div', { class: 'empty' }, t('scanForbidden')));
  const p = s.policy;
  const targets = el('textarea', { rows: 4, placeholder: '192.168.1.0/24\nexample.org' });
  const exclusions = el('textarea', { rows: 2, placeholder: '192.168.1.1' });
  const ports = el('input', { type: 'text', placeholder: p.allowed_ports });
  const workers = el('input', { type: 'number', min: 1, max: p.max_workers, value: Math.min(2, p.max_workers) });
  const rate = el('input', { type: 'number', min: 1, max: p.max_rate, value: Math.min(100, p.max_rate) });
  const timing = el('select', {}, [0, 1, 2, 3, 4].map((n) => el('option', { value: n, selected: n === 3 }, 'T' + n)));
  const web = el('input', { type: 'checkbox', checked: p.allow_web });
  const priv = el('input', { type: 'checkbox' });
  const token = el('input', { type: 'password', autocomplete: 'off', value: controlToken, placeholder: '…' });
  const message = el('div', {});
  const planBox = el('div', {});
  const builtin = p.presets || [];
  let mine = userPresets();
  const presetSel = el('select', {});
  const drawPresets = () => {
    mine = userPresets();
    presetSel.replaceChildren(el('option', { value: '' }, t('presetNone')),
      builtin.length ? el('optgroup', { label: t('presetBuiltin') }, builtin.map((pr, i) => el('option', { value: 'b' + i }, pr.name))) : null,
      mine.length ? el('optgroup', { label: t('presetMine') }, mine.map((pr, i) => el('option', { value: 'm' + i }, pr.name))) : null);
  };
  const pickedPreset = () => { const v = presetSel.value; return v[0] === 'b' ? builtin[Number(v.slice(1))] : v[0] === 'm' ? mine[Number(v.slice(1))] : null; };
  presetSel.addEventListener('change', () => {
    const pr = pickedPreset();
    delPreset.hidden = presetSel.value[0] !== 'm';
    if (!pr) return;
    const num = (v, d, max) => Math.min(Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d, max);
    targets.value = pr.targets.join('\n'); exclusions.value = (pr.exclusions || []).join('\n'); ports.value = pr.ports || '';
    workers.value = num(pr.workers, 2, p.max_workers); rate.value = num(pr.rate, 100, p.max_rate); timing.value = String(Number.isInteger(pr.timing) && pr.timing >= 0 && pr.timing <= 4 ? pr.timing : 3);
    web.checked = !!pr.web && p.allow_web; priv.checked = !!pr.privileged && p.allow_privileged;
  });
  const delPreset = el('button', { class: 'sec', hidden: true, onclick: () => {
    const pr = pickedPreset();
    if (!pr) return;
    storeUserPresets(mine.filter((x) => x.name !== pr.name)); drawPresets(); presetSel.value = ''; delPreset.hidden = true;
  } }, t('presetDelete'));
  drawPresets();

  const list = (box) => box.value.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
  const request = () => ({ targets: list(targets), exclusions: list(exclusions), ports: ports.value.trim(), workers: Number(workers.value), rate: Number(rate.value), timing: Number(timing.value), web: web.checked, privileged: priv.checked });
  const remember = () => { controlToken = token.value.trim(); try { sessionStorage.setItem('proculus.token', controlToken); } catch (e) { /* ignore */ } };
  const fail = (e) => { if (e instanceof LoginRequired) throw e; message.replaceChildren(el('div', { class: 'err' }, e.message)); };

  const planBtn = tip(t('plan'), t('tipPlan'), el('button', { class: 'sec', onclick: async () => {
    remember(); message.replaceChildren(); planBox.replaceChildren();
    try {
      const r = await post('/api/scan/plan', request());
      const lines = [r.addresses + ' ' + t('addresses'), r.chunks + ' ' + t('chunksN') + ' (' + r.chunk_size + ')', r.workers + ' × ' + r.rate + ' pkt/s', t('estimate') + ': ' + Math.round(r.discovery_estimate_seconds / 6) / 10 + ' min'];
      if (r.excluded) lines.push(r.excluded + ' ' + t('excluded'));
      if (r.domains) lines.push(r.domains + ' ' + t('domainsN'));
      planBox.replaceChildren(el('div', { class: 'eta-box' }, el('ul', { class: 'reasons' }, lines.concat(r.warnings).map((l) => el('li', {}, l)))));
    } catch (e) { fail(e); }
  } }, t('plan')));
  const saveBtn = el('button', { class: 'sec', onclick: () => {
    message.replaceChildren();
    const r = request();
    if (!r.targets.length) { message.replaceChildren(el('div', { class: 'err' }, t('presetNeedTargets'))); return; }
    const name = (window.prompt(t('presetSaveAsk'), pickedPreset() && presetSel.value[0] === 'm' ? pickedPreset().name : '') || '').trim().slice(0, 60);
    if (!name) return;
    const keep = { name, targets: r.targets, exclusions: r.exclusions, ports: r.ports, workers: r.workers, rate: r.rate, timing: r.timing, web: r.web, privileged: r.privileged };
    storeUserPresets(userPresets().filter((x) => x.name !== name).concat([keep]));
    drawPresets(); presetSel.value = 'm' + (mine.length - 1); delPreset.hidden = false;
    message.replaceChildren(el('div', { class: 'ok-note' }, t('presetSaved') + ': ' + name));
  } }, t('presetSave'));
  const startBtn = tip(t('start'), t('tipStart'), el('button', { onclick: async () => {
    remember(); message.replaceChildren();
    try { await post('/api/scan', request()); onStarted(); } catch (e) { fail(e); }
  } }, '▶ ' + t('start')));

  const fieldset = el('fieldset', { class: 'plain' },
    field(t('presetLabel'), t('presetHint'), el('div', { class: 'toolbar', style: 'margin:0' }, presetSel, delPreset)),
    field(t('targets'), t('targetsHint'), targets, t('tipTargets')), field(t('exclusions'), t('exclusionsHint'), exclusions), field(t('ports'), t('portsHint'), ports),
    el('div', { class: 'row3' }, field(t('workers'), '', workers, t('tipWorkers')), field(t('rate'), '', rate, t('tipRate')), field(t('timing'), '', timing, t('tipTiming'))),
    p.allow_web ? tip(t('web'), t('tipWeb'), el('label', { class: 'check' }, web, ' ' + t('web'))) : null,
    p.allow_privileged ? el('label', { class: 'check' }, priv, ' ' + t('privileged')) : null,
    auth && auth.enabled ? null : field(t('token'), t('tokenHint'), token));
  const node = el('div', { class: 'card', id: 'tour-config' }, el('h3', {}, t('cfgTitle')),
    el('p', { class: 'sub', style: 'font-size:12px' }, t('limits') + ': ' + t('scope') + ' ' + p.scope + ' · ' + t('allowedPorts') + ' ' + p.allowed_ports + ' · ' + t('maxWorkers') + ' ' + p.max_workers + ' · ' + t('maxRate') + ' ' + p.max_rate),
    fieldset, el('div', { class: 'toolbar', id: 'tour-start', style: 'margin-top:14px;margin-bottom:0' }, startBtn, planBtn, saveBtn), message, planBox);
  node.setBusy = (busy) => { fieldset.disabled = busy; startBtn.disabled = busy; planBtn.disabled = busy; saveBtn.disabled = busy; };
  return node;
}

// ---------------------------------------------------------------- views
function summaryText(d, hosts) {
  const L = ['PROCULUS — ' + t('summaryTitle'), '', t('lastRun') + ': #' + d.run.id + ' · ' + when(d.run.started) + ' · ' + t('source') + ': ' + d.run.source,
    t('hosts') + ': ' + d.run.hosts + ' · ' + t('servicesN') + ': ' + d.run.services + ' · ' + t('webServices') + ': ' + d.web_services + ' · ' + t('detections') + ': ' + d.detections];
  if (d.changes) {
    const c = d.changes;
    L.push(t('sinceLast') + ': +' + c.new_hosts + ' / -' + c.gone_hosts + ' ' + t('hosts').toLowerCase() + ', +' + c.new_services + ' / -' + c.gone_services + ' / ~' + c.changed_services + ' ' + t('servicesN').toLowerCase() + ', ' + c.web_changes + ' ' + t('webChanges').toLowerCase());
  }
  L.push('', t('topFindings') + ':');
  if (!d.top.length) L.push('  ' + t('noFindings'));
  d.top.forEach((f) => L.push('  [' + f.score + '] ' + f.ip + ':' + f.port + '/' + f.protocol + '  ' + f.service + (f.title ? ' — ' + f.title : '') + (f.reasons[0] ? '  (' + f.reasons[0] + ')' : '')));
  if (hosts && hosts.attention.length) {
    L.push('', t('attention') + ':');
    hosts.attention.slice(0, 15).forEach((a) => L.push('  ' + a.ip + '  ' + t('state_' + a.state) + '  ' + Math.round(a.existence * 100) + '%'));
  }
  return L.join('\n');
}

function downloadText(name, text) {
  const a = el('a', { href: 'data:text/plain;charset=utf-8,' + encodeURIComponent(text), download: name });
  document.body.append(a);
  a.click();
  a.remove();
}

async function viewDashboard() {
  const [d, hosts, scan] = await Promise.all([api('/api/dashboard'), api('/api/hosts').catch(() => null), api('/api/scan').catch(() => ({ enabled: false }))]);
  const empty = d.empty;
  const count = (cats) => empty ? 0 : d.categories.filter((c) => cats.includes(c.category)).reduce((a, c) => a + c.count, 0);
  const unstable = hosts ? (hosts.counts.flapping || 0) + (hosts.counts.stale || 0) : 0;

  const kpis = el('div', { class: 'grid-4', id: 'tour-kpi' },
    kpi(t('kpiHosts'), empty ? 0 : d.run.hosts, '', !empty && d.previous ? deltaNote(d.run.hosts - d.previous.hosts) : null, t('tipHosts')),
    kpi(t('kpiServices'), empty ? 0 : d.run.services, 'accent', !empty && d.previous ? deltaNote(d.run.services - d.previous.services) : null, t('tipServices')),
    kpi(t('kpiInteresting'), count(['admin', 'staging']), 'warn', null, t('tipInteresting')),
    kpi(t('kpiUnstable'), unstable, 'danger', null, t('tipUnstable')));

  // scan configuration (left) and live telemetry (right)
  const telemetry = buildTelemetry();
  telemetry.update(scan);
  let tick = null;
  const form = scanFormCard(scan, () => { if (tick) tick(); });
  if (form.setBusy) form.setBusy(!!scan.state && scan.state !== 'idle');
  telemetry.stopBtn.addEventListener('click', async () => {
    telemetry.stopBtn.disabled = true;
    try { await post('/api/scan/stop'); } catch (e) { if (e instanceof LoginRequired) throw e; alert(e.message); }
    if (tick) tick();
  });
  tick = startMonitor(scan, (s, prev) => {
    telemetry.update(s);
    if (form.setBusy) form.setBusy(s.state !== 'idle');
    if (prev && prev.state !== 'idle' && s.state === 'idle') { stopMonitor(); render(); } // the scan ended: refresh the figures once
  });

  const summary = el('div', { class: 'card summary-card', id: 'tour-summary' },
    el('div', { class: 'toolbar', style: 'justify-content:space-between' }, el('h3', { style: 'margin:0' }, '📋 ' + t('summaryTitle')),
      el('div', { class: 'toolbar', style: 'margin:0' },
        empty ? null : el('button', { class: 'sec', onclick: () => go('results', { view: 'services', run: d.run.id }) }, t('viewServices')),
        tip(t('saveTxt'), t('tipSaveTxt'), el('button', { disabled: empty, onclick: () => downloadText('proculus-run-' + (empty ? 0 : d.run.id) + '.txt', summaryText(d, hosts)) }, t('saveTxt'))))),
    empty ? el('div', { class: 'summary-report-box mono' }, t('noSummary')) : el('div', {},
      d.changes ? el('div', { style: 'margin-bottom:10px' }, el('span', { class: 'badge b-green' }, '+' + d.changes.new_hosts + ' ' + t('newHosts').toLowerCase()), ' ', el('span', { class: 'badge b-red' }, '−' + d.changes.gone_hosts + ' ' + t('goneHosts').toLowerCase()), ' ',
        el('span', { class: 'badge b-green' }, '+' + d.changes.new_services + ' ' + t('newServices').toLowerCase()), ' ', el('span', { class: 'badge b-red' }, '−' + d.changes.gone_services + ' ' + t('goneServices').toLowerCase()), ' ',
        el('span', { class: 'badge b-warn' }, d.changes.changed_services + ' ' + t('changedServices').toLowerCase()), ' ', el('span', { class: 'badge b-warn' }, d.changes.web_changes + ' ' + t('webChanges').toLowerCase())) : el('p', { class: 'sub' }, t('firstRun')),
      el('div', { class: 'summary-report-box mono' }, summaryText(d, hosts))));

  const top = el('div', { class: 'card' }, el('h3', {}, t('topFindings')),
    !empty && d.top.length ? el('div', { class: 'table-wrap' }, el('table', {}, servicesHead(), el('tbody', {}, d.top.map((f) => serviceRow(f, () => go('results', { view: 'services', q: f.ip })))))) : el('p', { class: 'sub' }, t('noFindings')));

  const charts = empty ? null : el('div', { class: 'grid-3' },
    el('div', { class: 'card' }, el('h3', {}, t('byLevel')), bars(d.levels.map((l) => ({ name: t(l.level), count: l.count, level: l.level })), (r) => r.name, (r) => r.level)),
    el('div', { class: 'card' }, el('h3', {}, t('byCategory')), bars(d.categories, (r) => r.category)),
    el('div', { class: 'card' }, el('h3', {}, t('technologies')), bars(d.technologies, (r) => r.name)));

  const names = ['new', 'active', 'flapping', 'stale', 'gone'];
  const stability = el('div', { class: 'card' }, el('h3', {}, t('stabilityTitle')),
    hosts ? el('div', { style: 'margin-bottom:10px' }, names.map((n) => el('span', { class: 'chip state-' + n }, t('state_' + n) + ': ' + (hosts.counts[n] || 0)))) : null,
    hosts && hosts.attention.length ? el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['address', 'hostname', 'stateCol', 'existence', 'sightingsCol', 'lastRunCol'].map((k) => el('th', {}, t(k))))),
      el('tbody', {}, hosts.attention.map((a) => el('tr', {}, el('td', { class: 'mono' }, a.ip), el('td', {}, a.hostname), el('td', {}, el('span', { class: 'state-' + a.state }, t('state_' + a.state)), a.time_dependent ? ' · ' + t('timeDep') : ''),
        el('td', {}, Math.round(a.existence * 100) + '%'), el('td', {}, a.sightings + '/' + a.observations), el('td', {}, '#' + a.last_run)))))) : el('p', { class: 'sub' }, t('allStable')));

  return el('div', {}, kpis, el('div', { class: 'grid-2' }, form, telemetry.node), summary, top, charts, stability);
}

// ---- results: services (with filters and editing), runs, edits
async function viewServices(params) {
  const runs = await api('/api/runs');
  if (!runs.length) return el('div', { class: 'card empty' }, el('h3', {}, t('noRuns')), el('p', {}, t('noRunsHint')));
  const state = { run: params.run || 'latest', q: params.q || '', min: params.min || '0', offset: Number(params.offset || 0), hide: params.hide === '1', edited: params.edited === '1' };
  const out = el('div', {});
  const table = el('div', {});

  async function load() {
    table.replaceChildren(el('p', { class: 'sub' }, t('loading')));
    try {
      const r = await api('/api/services?' + qs({ run: state.run, q: state.q, min_score: state.min === '0' ? '' : state.min, limit: 50, offset: state.offset, hide: state.hide ? '1' : '', edited: state.edited ? '1' : '' }));
      const from = r.total ? r.offset + 1 : 0, to = Math.min(r.offset + r.limit, r.total);
      table.replaceChildren(
        r.services.length ? el('div', { class: 'table-wrap' }, el('table', {}, servicesHead(), el('tbody', {}, r.services.map((f) => serviceRow(f))))) : el('div', { class: 'empty' }, t('none')),
        el('div', { class: 'pager' }, el('span', {}, from + '–' + to + ' ' + t('of') + ' ' + r.total),
          el('button', { class: 'sec', disabled: r.offset === 0, onclick: () => { state.offset = Math.max(0, state.offset - r.limit); load(); } }, t('prev')),
          el('button', { class: 'sec', disabled: to >= r.total, onclick: () => { state.offset += r.limit; load(); } }, t('next'))));
    } catch (e) { if (e instanceof LoginRequired) throw e; table.replaceChildren(el('div', { class: 'err' }, t('error') + ': ' + e.message)); }
  }

  const runSel = el('select', { style: 'width:auto', onchange: (e) => { state.run = e.target.value; state.offset = 0; load(); } },
    el('option', { value: 'latest' }, t('run') + ': ' + t('latest')), runs.map((r) => el('option', { value: String(r.id), selected: String(r.id) === state.run }, t('run') + ' #' + r.id + ' · ' + when(r.started))));
  const search = el('input', { class: 'grow', type: 'search', placeholder: t('search'), value: state.q });
  let timer = null;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { state.q = search.value.trim(); state.offset = 0; load(); }, 250); });
  const minSel = el('select', { style: 'width:auto', onchange: (e) => { state.min = e.target.value; state.offset = 0; load(); } },
    [['0', t('any')], ['15', '≥ 15 (' + t('low') + ')'], ['40', '≥ 40 (' + t('medium') + ')'], ['70', '≥ 70 (' + t('high') + ')']].map(([v, l]) => el('option', { value: v, selected: v === state.min }, t('minScore') + ': ' + l)));
  const hideBox = el('input', { type: 'checkbox', checked: state.hide, onchange: (e) => { state.hide = e.target.checked; state.offset = 0; load(); } });
  const editedBox = el('input', { type: 'checkbox', checked: state.edited, onchange: (e) => { state.edited = e.target.checked; state.offset = 0; load(); } });
  out.append(el('div', { class: 'card' }, el('h3', {}, t('resultsTitle')),
    el('div', { class: 'toolbar' }, search, minSel, runSel, el('label', { class: 'check', style: 'margin:0' }, hideBox, ' ' + t('hideIgnored')), el('label', { class: 'check', style: 'margin:0' }, editedBox, ' ' + t('onlyEdited'))), table));
  load();
  return out;
}

async function viewRuns() {
  const runs = await api('/api/runs');
  if (!runs.length) return el('div', { class: 'card empty' }, el('h3', {}, t('noRuns')), el('p', {}, t('noRunsHint')));
  return el('div', { class: 'card' }, el('h3', {}, t('runs')), el('div', { class: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {}, ['id', 'started', 'finished', 'source', 'hosts', 'servicesN', ''].map((k) => el('th', {}, k ? t(k) : '')))),
    el('tbody', {}, runs.map((r, i) => el('tr', {},
      el('td', {}, '#' + r.id), el('td', {}, when(r.started)), el('td', {}, when(r.finished)), el('td', {}, r.source), el('td', {}, String(r.hosts)), el('td', {}, String(r.services)),
      el('td', {}, el('button', { class: 'sec', onclick: () => go('results', { view: 'services', run: r.id }) }, t('open')), ' ',
        i + 1 < runs.length ? el('button', { class: 'sec', onclick: () => go('changes', { before: runs[i + 1].id, after: r.id }) }, t('compare')) : null)))))));
}

async function viewEdits() {
  const edits = await api('/api/edits');
  const rows = edits.map((e) => {
    const target = e.port ? e.ip + ':' + e.port + '/' + e.protocol : e.ip;
    return el('tr', {}, el('td', { class: 'mono' }, target), el('td', {}, e.hostname || ''), el('td', {}, e.environment ? t('env_' + e.environment) : ''),
      el('td', {}, e.status ? el('span', { class: 'chip st-' + e.status }, t('st_' + e.status)) : ''), el('td', {}, e.priority !== undefined ? String(e.priority) : ''),
      el('td', {}, (e.tags || []).map((x) => el('span', { class: 'chip' }, '#' + x))), el('td', { class: 'note' }, e.note || ''), el('td', {}, e.edited_by + ' · ' + when(e.edited_at)),
      can('data.edit') ? el('td', {}, el('button', { class: 'danger', onclick: async () => { try { await post('/api/edits/clear', e.port ? { ip: e.ip, port: e.port, protocol: e.protocol } : { ip: e.ip }); render(); } catch (err) { if (err instanceof LoginRequired) throw err; alert(err.message); } } }, t('removeEdits'))) : null);
  });
  return el('div', { class: 'card' }, el('h3', {}, t('edits')), el('p', { class: 'sub' }, t('editsHelp')),
    edits.length ? el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['target', 'hostnameLabel', 'environment', 'statusLabel', 'priorityLabel', 'tagsLabel', 'noteLabel', 'editedBy', can('data.edit') ? '' : null].filter((k) => k !== null).map((k) => el('th', {}, k ? t(k) : '')))), el('tbody', {}, rows)))
      : el('div', { class: 'empty' }, t('noEdits')));
}

async function viewResults(params) {
  const mode = ['services', 'runs', 'edits'].includes(params.view) ? params.view : 'services';
  const seg = el('div', { class: 'segmented' }, ['services', 'runs', 'edits'].map((m) => el('button', { class: m === mode ? 'on' : '', onclick: () => go('results', { view: m }) }, t('sub_' + m))));
  const inner = await ({ services: viewServices, runs: viewRuns, edits: viewEdits }[mode])(params);
  return el('div', {}, seg, inner);
}

// ---- changes between two runs
async function viewChanges(params) {
  const runs = await api('/api/runs');
  if (runs.length < 2) return el('div', { class: 'card empty' }, el('h3', {}, t('changes')), el('p', {}, t('pickTwo')));
  const before = params.before || String(runs[1].id), after = params.after || String(runs[0].id);
  const pick = (name, value) => el('select', { id: name, style: 'width:auto' }, runs.map((r) => el('option', { value: String(r.id), selected: String(r.id) === value }, '#' + r.id + ' · ' + when(r.started))));
  const selB = pick('before', before), selA = pick('after', after);
  const result = el('div', {});
  const key = (c) => c.ip + ':' + c.port + '/' + c.protocol;
  const LIMIT = 100;
  const more = (rows) => rows.length > LIMIT ? el('p', { class: 'sub' }, '… +' + (rows.length - LIMIT)) : null;
  const card = (title, cls, rows, body) => el('div', { class: 'card' }, el('h3', { class: cls }, title + ' (' + rows.length + ')'), body, more(rows));
  const list = (title, cls, rows, render) => rows.length ? card(title, cls, rows, el('div', { class: 'table-wrap' }, el('table', {}, el('tbody', {}, rows.slice(0, LIMIT).map(render))))) : null;
  const chips = (title, cls, rows) => rows.length ? card(title, cls, rows, el('div', {}, rows.slice(0, LIMIT * 3).map((h) => el('span', { class: 'chip mono' }, h)))) : null;

  try {
    if (before !== after) {
      const d = await api('/api/diff?' + qs({ before, after }));
      const none = !d.new_hosts.length && !d.gone_hosts.length && !d.new_services.length && !d.gone_services.length && !d.changed_services.length && !d.web_changes.length;
      const sections = [
        chips(t('newHosts'), 'tag-new', d.new_hosts), chips(t('goneHosts'), 'tag-gone', d.gone_hosts),
        list(t('newServices'), 'tag-new', d.new_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.after))),
        list(t('goneServices'), 'tag-gone', d.gone_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.before))),
        list(t('changedServices'), 'tag-chg', d.changed_services, (s) => el('tr', {}, el('td', { class: 'mono' }, key(s)), el('td', {}, s.before + ' → ' + s.after))),
        list(t('webChanges'), 'tag-chg', d.web_changes, (w) => el('tr', {}, el('td', { class: 'mono' }, key(w)), el('td', {}, w.what), el('td', {}, w.before || '—'), el('td', {}, '→ ' + (w.after || '—')))),
      ].filter(Boolean);
      result.append(...(none ? [el('div', { class: 'card empty' }, t('noChanges'))] : sections));
    } else result.append(el('div', { class: 'card empty' }, t('pickTwo')));
  } catch (e) { if (e instanceof LoginRequired) throw e; result.append(el('div', { class: 'err' }, t('error') + ': ' + e.message)); }

  return el('div', {}, el('div', { class: 'card' }, el('h3', {}, t('tab_changes')),
    el('div', { class: 'toolbar', style: 'margin:0' }, t('before'), selB, t('after'), selA, el('button', { onclick: () => go('changes', { before: selB.value, after: selA.value }) }, t('show')))), result);
}

// ---- tabs that are announced but not built yet
function viewSoon(textKey, titleKey) {
  return () => el('div', { class: 'card' }, el('h3', {}, t(titleKey)), el('div', { class: 'empty' }, el('div', { style: 'font-size:34px' }, '🛠'), el('b', {}, t('soonTitle')), el('p', {}, t(textKey))));
}

// ---- administration: users, roles, audit log
// Admin > Scanning: what the "New scan" form may do. The gateway validates everything (and the operator's ceiling).
function scanSettingsCard(c, done) {
  const on = el('input', { type: 'checkbox', checked: c.enabled });
  const scope = el('input', { type: 'text', value: c.scope, autocomplete: 'off', spellcheck: 'false' });
  const ports = el('input', { type: 'text', value: c.allowed_ports, autocomplete: 'off', spellcheck: 'false' });
  const workers = el('input', { type: 'number', min: '1', max: '64', value: String(c.max_workers) });
  const rate = el('input', { type: 'number', min: '1', max: '100000', value: String(c.max_rate) });
  const web = el('input', { type: 'checkbox', checked: c.allow_web });
  const priv = el('input', { type: 'checkbox', checked: c.allow_privileged });
  const reserved = el('input', { type: 'checkbox', checked: c.allow_reserved });

  // the same presets as on the scan form, here only to fill in the scope and ports
  const merge = (input, items) => { const have = input.value.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean); items.forEach((x) => { if (!have.includes(x)) have.push(x); }); input.value = have.join(','); };
  const all = (c.presets || []).concat(userPresets());
  const presetButtons = all.map((pr) => el('button', { class: 'sec', onclick: () => { merge(scope, pr.targets); merge(ports, (pr.ports || '').split(',')); } }, '+ ' + pr.name));

  const save = () => done(async () => {
    await post('/api/scan/config', { enabled: on.checked, scope: scope.value.trim(), allowed_ports: ports.value.trim(), max_workers: Number(workers.value), max_rate: Number(rate.value),
      allow_web: web.checked, allow_privileged: priv.checked, allow_reserved: reserved.checked, });
  });
  return el('div', { class: 'card' }, el('h3', {}, t('scanCfgTitle')), el('p', { class: 'sub' }, t('scanCfgIntro')),
    el('label', { class: 'check' }, on, ' ' + t('scanCfgEnabled')),
    el('div', { class: 'grid-2' }, field(t('scanCfgScope'), t('scanCfgScopeHint'), scope), field(t('scanCfgPorts'), t('scanCfgPortsHint'), ports),
      field(t('scanCfgWorkers'), '', workers), field(t('scanCfgRate'), '', rate)),
    el('label', { class: 'check' }, web, ' ' + t('scanCfgWeb')), el('label', { class: 'check' }, priv, ' ' + t('scanCfgPriv')), el('label', { class: 'check' }, reserved, ' ' + t('scanCfgReserved')),
    el('p', { class: 'sub', style: 'font-size:12px' }, t('scanCfgCeiling') + ': ', el('span', { class: 'mono' }, c.ceiling || t('scanCfgNoCeiling'))),
    presetButtons.length ? el('div', { class: 'toolbar' }, el('span', { class: 'sub', style: 'font-size:12px' }, t('presetAddTo')), ...presetButtons) : null,
    el('div', { class: 'toolbar' }, el('button', { onclick: save }, t('scanCfgSave'))));
}

async function viewAdmin() {
  if (!auth || !auth.enabled) return el('div', { class: 'card empty' }, el('h3', {}, t('adminTitle')), el('p', {}, t('authOff')));
  if (!can('users.manage')) return el('div', { class: 'card empty' }, el('p', {}, t('forbidden')));
  const [users, roles, audit, scanCfg] = await Promise.all([api('/api/users'), api('/api/roles'), api('/api/audit?limit=100'), can('config.manage') ? api('/api/scan/config') : Promise.resolve(null)]);
  const message = el('div', {});
  const done = async (fn) => {
    message.replaceChildren();
    try { await fn(); render(); } catch (e) { if (e instanceof LoginRequired) throw e; message.replaceChildren(el('div', { class: 'err' }, e.message)); }
  };
  const roleSelect = (value) => el('select', { style: 'width:auto' }, roles.map((r) => el('option', { value: r.name, selected: r.name === value }, roleLabel(r.name))));

  const rows = users.map((u) => {
    const sel = roleSelect(u.role);
    return el('tr', {}, el('td', {}, u.username), el('td', {}, sel, ' ', el('button', { class: 'sec', onclick: () => done(() => post('/api/users/update', { id: u.id, role: sel.value })) }, t('save'))),
      el('td', { class: u.disabled ? 'tag-gone' : 'tag-new' }, u.disabled ? t('disabled') : t('enabled')), el('td', {}, u.last_login ? when(u.last_login) : t('never')),
      el('td', {}, el('button', { class: 'sec', onclick: () => done(() => post('/api/users/update', { id: u.id, disabled: !u.disabled })) }, u.disabled ? t('enable') : t('disable')), ' ',
        el('button', { class: 'sec', onclick: () => { const pw = window.prompt(t('newPassword')); if (pw) done(() => post('/api/users/update', { id: u.id, password: pw })); } }, t('resetPassword'))));
  });
  const nu = el('input', { type: 'text', placeholder: t('username'), autocomplete: 'off' }), np = el('input', { type: 'password', placeholder: t('newPassword'), autocomplete: 'new-password' }), nr = roleSelect('viewer');

  const perms = el('div', { class: 'perms' });
  const checks = ['data.read', 'data.edit', 'data.create', 'data.delete', 'export', 'scan.run', 'config.manage', 'users.manage'].map((p) => {
    const box = el('input', { type: 'checkbox', value: p, checked: p === 'data.read' });
    perms.append(el('label', { class: 'check' }, box, ' ' + t('perm_' + p)));
    return box;
  });
  const rn = el('input', { type: 'text', placeholder: t('roleName'), autocomplete: 'off' }), rd = el('input', { type: 'text', placeholder: t('description'), autocomplete: 'off' });

  return el('div', {}, message, scanCfg ? scanSettingsCard(scanCfg, done) : null,
    el('div', { class: 'card' }, el('h3', {}, t('users')),
      el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['username', 'role', 'status', 'lastLogin', 'actions'].map((k) => el('th', {}, t(k))))), el('tbody', {}, rows))),
      el('div', { class: 'toolbar', style: 'margin-top:12px' }, nu, np, nr, el('button', { onclick: () => done(() => post('/api/users', { username: nu.value.trim(), password: np.value, role: nr.value })) }, t('addUser')))),
    el('div', { class: 'card' }, el('h3', {}, t('roles')),
      el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['role', 'description', 'permissions', 'users', ''].map((k) => el('th', {}, k === 'users' ? t('users') : k ? t(k) : '')))),
        el('tbody', {}, roles.map((r) => el('tr', {}, el('td', {}, roleLabel(r.name), r.builtin ? el('span', { class: 'chip' }, t('builtin')) : null), el('td', {}, r.description),
          el('td', {}, r.permissions.map((p) => el('span', { class: 'chip' }, t('perm_' + p)))), el('td', {}, String(r.users)),
          el('td', {}, r.builtin ? null : el('button', { class: 'danger', onclick: () => done(() => post('/api/roles/delete', { name: r.name })) }, t('deleteRole')))))))),
      el('h3', { style: 'margin-top:16px' }, t('addRole')), el('div', { class: 'toolbar' }, rn, rd), perms,
      el('div', { class: 'toolbar' }, el('button', { onclick: () => done(() => post('/api/roles', { name: rn.value.trim(), description: rd.value, permissions: checks.filter((b) => b.checked).map((b) => b.value) })) }, t('addRole')))),
    el('div', { class: 'card' }, el('h3', {}, t('audit')),
      el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['when_', 'who', 'action', 'entity', 'detail'].map((k) => el('th', {}, t(k))))),
        el('tbody', {}, audit.map((e) => el('tr', {}, el('td', { class: 'mono' }, when(e.at)), el('td', {}, e.user || '—'), el('td', {}, e.action), el('td', { class: 'mono' }, e.entity), el('td', {}, e.detail))))))));
}

// ---------------------------------------------------------------- sign in and first-run setup (one card on its own screen)
function authCard(kind) {
  const setup = kind === 'setup';
  const token = setup ? el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false' }) : null;
  const user = el('input', { type: 'text', autocomplete: 'username' });
  const pass = el('input', { type: 'password', autocomplete: setup ? 'new-password' : 'current-password' });
  const again = setup ? el('input', { type: 'password', autocomplete: 'new-password' }) : null;
  const message = el('div', {});
  const submit = async () => {
    message.replaceChildren();
    if (setup && pass.value !== again.value) { message.replaceChildren(el('div', { class: 'err' }, t('passwordsDiffer'))); return; }
    try {
      const r = setup ? await post('/api/setup', { setup_token: token.value.trim(), username: user.value.trim(), password: pass.value }) : await post('/api/login', { username: user.value.trim(), password: pass.value });
      if (setup) auth = { enabled: true, hasUsers: true, setupRequired: false };
      setSession(r.token, r.user);
      location.hash = '#/dashboard';
      render();
    } catch (e) { message.replaceChildren(el('div', { class: 'err' }, e.message)); pass.value = ''; if (again) again.value = ''; }
  };
  (again || pass).addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  user.addEventListener('keydown', (e) => { if (e.key === 'Enter') pass.focus(); });
  return el('div', { class: 'auth-card' },
    el('div', { class: 'auth-head' }, emblem(84), el('div', { class: 'brand-title', style: 'font-size:24px;margin-top:4px' }, 'PROCULUS'), el('div', { class: 'brand-sub', style: 'font-size:12px;margin-top:4px' }, setup ? t('setupSub') : t('gateSub')),
      el('div', { style: 'margin-top:8px' }, el('span', { class: 'badge ' + (setup ? 'b-blue' : 'b-green') }, setup ? t('setupTitle') : t('gateBadge')))),
    setup ? el('p', { class: 'sub', style: 'font-size:12.5px' }, t('setupIntro')) : null,
    !setup && auth && !auth.hasUsers ? el('div', { class: 'err' }, el('b', {}, t('noUsers')), ' ', t('noUsersHint')) : null,
    setup ? field(t('setupToken'), t('setupTokenHint'), token) : null,
    field(t('username'), '', user), field(t('password'), setup ? t('newPassword') : '', pass), setup ? field(t('confirmPassword'), '', again) : null,
    el('button', { style: 'width:100%;margin-top:16px', onclick: submit }, setup ? t('createAdmin') : t('loginBtn')), message);
}

function langSelect() {
  const sel = el('select', { 'aria-label': 'Language', style: 'width:auto', onchange: () => { lang = sel.value; try { localStorage.setItem('proculus.lang', lang); } catch (e) { /* ignore */ } render(); } },
    el('option', { value: 'pl' }, 'Polski'), el('option', { value: 'en' }, 'English'));
  sel.value = lang;
  return sel;
}

function showGate() {
  stopMonitor();
  $('#appScreen').hidden = true;
  const gate = $('#gate');
  gate.hidden = false;
  gate.replaceChildren(el('div', { class: 'gate-lang' }, langSelect()), authCard(auth && auth.setupRequired ? 'setup' : 'login'));
}

// ---------------------------------------------------------------- shell: header and tabs
let scanPolicy = null;
function renderHeader() {
  const bar = $('#topbar');
  const signedIn = session.user;
  bar.replaceChildren(
    el('div', { class: 'brand-wrap' }, emblem(42), el('div', {}, el('div', { class: 'brand-title' }, 'PROCULUS'), el('div', { class: 'brand-sub' }, t('brandSub'))),
      el('span', { class: 'badge ' + (auth && auth.enabled ? 'b-green' : 'b-red') }, auth && auth.enabled ? t('badgeAuthOn') : t('badgeAuthOff')),
      scanPolicy ? el('span', { class: 'badge b-blue mono', title: t('allowedPorts') + ': ' + scanPolicy.allowed_ports }, t('badgeScope') + ': ' + scanPolicy.scope) : null),
    el('div', { class: 'head-right' },
      el('button', { class: 'sec', onclick: () => startTour(true) }, '🧭 ' + t('tourBtn')), langSelect(),
      signedIn ? el('span', {}, t('account') + ': ', el('b', {}, session.user.username), ' ', el('span', { class: 'badge b-blue' }, roleLabel(session.user.role))) : null,
      signedIn ? el('button', { class: 'sec', onclick: async () => { try { await post('/api/logout'); } catch (e) { /* the session may be gone already */ } setSession('', null); location.hash = '#/dashboard'; render(); } }, t('signOut')) : null));
}

const ROUTES = { dashboard: viewDashboard, results: viewResults, changes: viewChanges, targets: viewSoon('soonTargets', 'tab_targets'), signatures: viewSoon('soonSignatures', 'tab_signatures'), schedule: viewSoon('soonSchedule', 'tab_schedule'), admin: viewAdmin };
const ROUTE_PERMISSION = { dashboard: 'data.read', results: 'data.read', changes: 'data.read', targets: 'data.read', signatures: 'data.read', schedule: 'data.read', admin: 'users.manage' };
const SOON = new Set(['targets', 'signatures', 'schedule']);
const ALIASES = { services: ['results', { view: 'services' }], runs: ['results', { view: 'runs' }], edits: ['results', { view: 'edits' }], scan: ['dashboard', {}] }; // links of the earlier layout keep working

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [rawName, query] = raw.split('?');
  let params = {};
  for (const part of (query || '').split('&')) {
    if (!part) continue;
    const [k, v] = part.split('=');
    try { params[decodeURIComponent(k)] = decodeURIComponent(v || ''); } catch (e) { /* ignore a malformed pair */ }
  }
  let name = rawName;
  if (ALIASES[name]) { params = Object.assign({}, ALIASES[name][1], params); name = ALIASES[name][0]; }
  return { name: ROUTES[name] ? name : 'dashboard', params };
}

function renderNav(active) {
  const nav = $('#nav');
  nav.replaceChildren(...Object.keys(ROUTES).filter((n) => (n !== 'admin' || (auth && auth.enabled)) && can(ROUTE_PERMISSION[n])).map((n) =>
    el('button', { class: 'tab-btn' + (n === active ? ' active' : '') + (SOON.has(n) ? ' soon' : ''), role: 'tab', 'aria-selected': n === active ? 'true' : 'false', onclick: () => go(n) }, t('tab_' + n))));
}

let renderToken = 0;
async function render() {
  stopMonitor();
  const token = ++renderToken;
  document.documentElement.lang = lang;
  const view = $('#view');
  try {
    // asked again whenever nobody is signed in, so a server that was restarted or set up meanwhile is noticed
    if (!auth || !session.user) auth = await fetch('/api/auth').then((r) => (r.ok ? r.json() : { enabled: false })).then((a) => ({ enabled: !!a.enabled, hasUsers: a.has_users !== false, setupRequired: !!a.setup_required })).catch(() => ({ enabled: false, hasUsers: true }));
    if (auth.enabled && session.token && !session.user) {
      try { session.user = (await api('/api/me')).user; } catch (e) { if (!(e instanceof LoginRequired)) throw e; }
    }
    if (token !== renderToken) return;
    if (auth.enabled && !session.user) { showGate(); return; }
    $('#gate').hidden = true;
    $('#appScreen').hidden = false;
    const { name, params } = parseHash();
    try { const s = await api('/api/scan'); scanPolicy = s.enabled ? s.policy : null; } catch (e) { if (e instanceof LoginRequired) throw e; scanPolicy = null; }
    if (token !== renderToken) return;
    renderHeader();
    renderNav(name);
    if (!can(ROUTE_PERMISSION[name])) { view.replaceChildren(el('div', { class: 'card empty' }, el('p', {}, t('forbidden')))); return; }
    view.replaceChildren(el('p', { class: 'sub' }, t('loading')));
    const node = await ROUTES[name](params);
    if (token !== renderToken) return;
    view.replaceChildren(el('div', { class: 'view' }, auth.enabled ? null : el('div', { class: 'err warn' }, t('openMode')), node));
    if (name === 'dashboard' && !params.notour) setTimeout(() => startTour(false), 500);
  } catch (e) {
    if (e instanceof LoginRequired) { if (token === renderToken) { auth = null; render(); } return; }
    if (token === renderToken) view.replaceChildren(el('div', { class: 'err' }, t('error') + ': ' + e.message));
  }
}

// ---------------------------------------------------------------- guided tour
// Differences from a naive version: the box is positioned only after the smooth scroll has stopped (so the
// measured position is the real one), the pointer is drawn by CSS and reset on every step, the position is
// recomputed on resize and scroll, the box does not slide in from a corner on the first step, and Esc and the
// arrow keys work. With reduced motion there is no smooth scrolling and no sliding.
const TOUR = [{ sel: '#tour-kpi', key: 'tour1' }, { sel: '#tour-config', key: 'tour2' }, { sel: '#tour-start', key: 'tour3' }, { sel: '#tour-telemetry', key: 'tour4' }, { sel: '#tour-summary', key: 'tour5' }];
let tourIdx = -1, tourTarget = null, tourBusy = false;
const tourDone = () => { try { return localStorage.getItem('proculus.tour') === '1'; } catch (e) { return false; } };

function settleScroll() {
  return new Promise((resolve) => {
    let last = -1, stable = 0;
    const t0 = performance.now();
    const step = () => {
      const y = window.scrollY;
      stable = y === last ? stable + 1 : 0;
      last = y;
      if (stable >= 6 || performance.now() - t0 > 1000) resolve(); else requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

function placeTour() {
  const box = $('#mascotBox');
  if (!tourTarget || !tourTarget.isConnected) return;
  const r = tourTarget.getBoundingClientRect(), w = Math.min(400, window.innerWidth * 0.92), h = box.offsetHeight, pad = 12;
  const clampTop = (v) => Math.max(pad, Math.min(window.innerHeight - h - pad, v));
  const clampLeft = (v) => Math.max(pad, Math.min(window.innerWidth - w - pad, v));
  let left, top, side;
  if (r.right + w + 28 <= window.innerWidth) { side = 'right'; left = r.right + 24; top = clampTop(r.top); }
  else if (r.left - w - 28 >= 0) { side = 'left'; left = r.left - w - 24; top = clampTop(r.top); }
  else if (r.bottom + h + 24 <= window.innerHeight) { side = 'below'; left = clampLeft(r.left + 20); top = r.bottom + 18; }
  else { side = 'above'; left = clampLeft(r.left + 20); top = clampTop(r.top - h - 18); }
  box.dataset.side = side;
  box.style.left = Math.round(left) + 'px';
  box.style.top = Math.round(top) + 'px';
}

async function showTourStep() {
  if (tourBusy) return;
  tourBusy = true;
  try {
    document.querySelectorAll('.tour-highlight').forEach((n) => n.classList.remove('tour-highlight'));
    let step = TOUR[tourIdx], target = document.querySelector(step.sel);
    while (!target && tourIdx < TOUR.length - 1) { tourIdx++; step = TOUR[tourIdx]; target = document.querySelector(step.sel); }
    if (!target) { endTour(); return; }
    tourTarget = target;
    const box = $('#mascotBox');
    box.replaceChildren(
      el('div', { class: 'mascot-header' }, el('div', { class: 'mascot-avatar' }, emblem(46)),
        el('div', {}, el('div', { style: 'font-weight:800;color:var(--accent);font-size:14.5px' }, t('tourTitle')), el('div', { style: 'font-size:11.5px;color:var(--muted)' }, t('tourStep') + ' ' + (tourIdx + 1) + ' ' + t('tourOf') + ' ' + TOUR.length))),
      el('div', { style: 'font-size:13px;line-height:1.5;margin-bottom:14px' }, t(step.key)),
      el('div', { class: 'tour-actions' }, el('button', { class: 'sec', onclick: endTour }, t('tourSkip')),
        el('div', { style: 'display:flex;gap:6px' }, el('button', { class: 'sec', disabled: tourIdx === 0, onclick: () => tourGo(-1) }, t('tourPrev')),
          el('button', { id: 'tourNextBtn', onclick: () => tourGo(1) }, tourIdx === TOUR.length - 1 ? t('tourFinish') : t('tourNext')))));
    target.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'center' });
    await settleScroll(); // measure only after the scroll has really stopped
    if (tourIdx < 0) return;
    target.classList.add('tour-highlight');
    placeTour();
    box.classList.add('show');
    requestAnimationFrame(() => box.classList.add('settled'));
    const next = $('#tourNextBtn');
    if (next) next.focus({ preventScroll: true });
  } finally { tourBusy = false; }
}

function tourGo(delta) {
  const i = tourIdx + delta;
  if (i < 0) return;
  if (i >= TOUR.length) { endTour(); return; }
  tourIdx = i;
  showTourStep();
}

function endTour() {
  tourIdx = -1;
  tourTarget = null;
  document.querySelectorAll('.tour-highlight').forEach((n) => n.classList.remove('tour-highlight'));
  $('#tourBackdrop').classList.remove('show');
  const box = $('#mascotBox');
  box.classList.remove('show', 'settled');
  try { localStorage.setItem('proculus.tour', '1'); } catch (e) { /* ignore */ }
}

async function startTour(force) {
  if (tourIdx >= 0 || (!force && tourDone())) return;
  if (parseHash().name !== 'dashboard') { location.hash = '#/dashboard?notour=1'; await render(); }
  if (!document.querySelector('#tour-kpi')) return; // the dashboard is not on screen (for example, signed out)
  tourIdx = 0;
  $('#tourBackdrop').classList.add('show');
  $('#mascotBox').classList.remove('settled');
  showTourStep();
}

let tourFrame = 0;
const retarget = () => { if (tourIdx < 0 || tourFrame) return; tourFrame = requestAnimationFrame(() => { tourFrame = 0; placeTour(); }); };
window.addEventListener('resize', retarget);
window.addEventListener('scroll', retarget, true);
document.addEventListener('keydown', (e) => {
  if (tourIdx < 0) return;
  if (e.key === 'Escape') endTour();
  else if (e.key === 'ArrowRight') tourGo(1);
  else if (e.key === 'ArrowLeft') tourGo(-1);
});
$('#tourBackdrop').addEventListener('click', endTour);

window.addEventListener('hashchange', () => { if (tourIdx >= 0) endTour(); render(); });
render();
