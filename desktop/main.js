// Proculus as a desktop application: starts the bundled "proculus" program on free loopback ports, shows its web
// UI in a window of its own, and stops it when the window closes. No browser is involved.
const { app, BrowserWindow, Menu, dialog, ipcMain, session, shell } = require('electron');
const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');

const isWin = process.platform === 'win32';
const isMac = process.platform === 'darwin';
if (process.platform === 'linux') app.commandLine.appendSwitch('no-sandbox'); // an AppImage cannot carry a SUID sandbox helper

// the first-run setup token is generated here and given to the server and to the page (see preload.js)
const setupToken = crypto.randomBytes(16).toString('hex');
let server = null, win = null, uiPort = 0, quitting = false, restarting = false, output = [], nmapPath = null, nmapWarned = false;
let simulate = process.argv.includes('--simulate') || process.env.PROCULUS_SIMULATE === '1';

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');
function loadSettings() {
	try { const s = JSON.parse(fs.readFileSync(settingsFile(), 'utf8')); if (s && s.simulate === true && !process.argv.includes('--real')) simulate = true; } catch (e) { /* first run */ }
}
function saveSettings() {
	try { fs.mkdirSync(app.getPath('userData'), { recursive: true }); fs.writeFileSync(settingsFile(), JSON.stringify({ simulate })); } catch (e) { /* not critical */ }
}

function serverPath() {
	if (process.env.PROCULUS_BIN) return process.env.PROCULUS_BIN;
	const base = app.isPackaged ? path.join(process.resourcesPath, 'server') : path.join(__dirname, 'server');
	return path.join(base, isWin ? 'proculus.exe' : 'proculus');
}

// An application opened from Finder / the Start menu gets a minimal PATH (no /opt/local/bin, no /opt/homebrew/bin), so
// nmap is looked for in the usual install locations as well; its full path is given to the program.
function findNmap() {
	const exe = isWin ? 'nmap.exe' : 'nmap';
	const extra = isWin ? ['C:\\Program Files (x86)\\Nmap', 'C:\\Program Files\\Nmap']
		: ['/opt/local/bin', '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/snap/bin', '/usr/local/sbin', '/opt/local/sbin'];
	for (const dir of (process.env.PATH || '').split(path.delimiter).concat(extra)) {
		if (!dir) continue;
		const candidate = path.join(dir, exe);
		try { fs.accessSync(candidate, fs.constants.X_OK); if (fs.statSync(candidate).isFile()) return candidate; } catch (e) { /* not here */ }
	}
	return null;
}

function freePort() {
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.on('error', reject);
		s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
	});
}

function ping(port) {
	return new Promise((resolve) => {
		const req = http.get({ host: '127.0.0.1', port, path: '/api/auth', timeout: 1500 }, (res) => { res.resume(); resolve(res.statusCode === 200); });
		req.on('error', () => resolve(false));
		req.on('timeout', () => { req.destroy(); resolve(false); });
	});
}

async function startServer() {
	const bin = serverPath();
	if (!fs.existsSync(bin)) throw new Error('The Proculus program was not found at ' + bin);
	try { fs.chmodSync(bin, 0o755); } catch (e) { /* read-only location: it is already executable */ }
	const dataDir = path.join(app.getPath('userData'), simulate ? 'data-sim' : 'data');
	fs.mkdirSync(dataDir, { recursive: true });
	const apiPort = await freePort();
	uiPort = await freePort();
	const args = ['serve', '--store', dataDir, '--port', String(apiPort), '--ui-port', String(uiPort)];
	nmapPath = simulate ? null : findNmap();
	if (simulate) args.push('--simulate');
	else {
		args.push('--scan-ceiling', '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16');
		if (nmapPath) args.push('--scan-nmap', nmapPath);
	}
	output = [];
	server = spawn(bin, args, { cwd: dataDir, windowsHide: true, env: Object.assign({}, process.env, { PROCULUS_SETUP_TOKEN: setupToken }) });
	const keep = (chunk) => { output.push(...chunk.toString().split(/\r?\n/).filter(Boolean)); output = output.slice(-30); };
	server.stdout.on('data', keep);
	server.stderr.on('data', keep);
	const mine = server;
	server.on('exit', (code) => {
		if (server === mine) server = null;
		if (quitting || restarting) return;
		dialog.showErrorBox('Proculus stopped', 'The Proculus program exited (code ' + code + ').\n\n' + output.slice(-12).join('\n'));
		app.quit();
	});
	for (let i = 0; i < 120; i++) { // up to 30 s
		if (!server) throw new Error('The Proculus program exited while starting:\n' + output.slice(-12).join('\n'));
		if (await ping(uiPort)) return;
		await new Promise((r) => setTimeout(r, 250));
	}
	throw new Error('The Proculus program did not answer in 30 seconds:\n' + output.slice(-12).join('\n'));
}

function stopServer() {
	const s = server;
	server = null;
	if (!s || s.exitCode !== null) return Promise.resolve();
	return new Promise((resolve) => {
		const done = () => resolve();
		s.once('exit', done);
		try {
			if (isWin) execFileSync('taskkill', ['/pid', String(s.pid), '/T', '/F'], { windowsHide: true });
			else s.kill('SIGTERM');
		} catch (e) { done(); }
		setTimeout(() => { try { s.kill('SIGKILL'); } catch (e) { /* gone */ } done(); }, 3000);
	});
}

const splash = (text) => 'data:text/html;charset=utf-8,' + encodeURIComponent(
	'<!doctype html><meta charset="utf-8"><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;font:16px system-ui,sans-serif;background:#f4f7fb;color:#0077e6">' +
	'<div style="text-align:center"><div style="font-size:28px;font-weight:800;letter-spacing:.12em">PROCULUS</div><p style="color:#5b6b80">' + text + '</p></div>');

async function load() {
	win.loadURL(splash(simulate ? 'Starting (simulation)…' : 'Starting…'));
	try {
		await startServer();
	} catch (e) {
		dialog.showErrorBox('Proculus could not start', String(e.message || e));
		app.quit();
		return;
	}
	if (win) win.loadURL('http://127.0.0.1:' + uiPort + '/');
	if (!simulate && !nmapPath && !nmapWarned && win) { // real scans cannot work without nmap: say so once, and offer the simulation
		nmapWarned = true;
		const choice = await dialog.showMessageBox(win, {
			type: 'warning', title: 'nmap not found', buttons: ['Continue', 'Use the simulation'], defaultId: 0, cancelId: 0,
			message: 'nmap was not found on this computer.',
			detail: 'Real scans need nmap (https://nmap.org/download). The simulation (an emulated network) works without it and can be switched on in the Proculus menu at any time.',
		});
		if (choice.response === 1) switchMode(true);
	}
}

function createWindow() {
	win = new BrowserWindow({
		width: 1360, height: 900, minWidth: 960, minHeight: 640, title: 'Proculus', backgroundColor: '#f4f7fb',
		webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: false },
	});
	win.setMenuBarVisibility(false);
	// the window shows the local UI and nothing else: no other site, no pop-ups
	win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
	win.webContents.on('will-navigate', (event, url) => {
		if (!url.startsWith('http://127.0.0.1:' + uiPort + '/') && !url.startsWith('data:text/html')) event.preventDefault();
	});
	win.on('closed', () => { win = null; });
	load();
}

async function switchMode(toSimulation) {
	if (simulate === toSimulation) return;
	simulate = toSimulation;
	saveSettings();
	restarting = true;
	await stopServer();
	restarting = false;
	if (win) await load();
}

function buildMenu() {
	const template = [
		...(isMac ? [{ role: 'appMenu' }] : []),
		{
			label: 'Proculus',
			submenu: [
				{ label: 'Simulation mode (emulated network)', type: 'checkbox', checked: simulate, click: (item) => switchMode(item.checked) },
				{ label: 'Open data folder', click: () => shell.openPath(app.getPath('userData')) },
				{ type: 'separator' },
				{ role: 'reload' },
				...(isMac ? [] : [{ type: 'separator' }, { role: 'quit' }]),
			],
		},
		{ role: 'editMenu' },
		{ role: 'viewMenu' },
		{ role: 'windowMenu' },
	];
	Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

if (!app.requestSingleInstanceLock()) {
	app.quit();
} else {
	app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
	ipcMain.on('proculus:token', (event) => {
		const url = event.senderFrame ? event.senderFrame.url : '';
		event.returnValue = url.startsWith('http://127.0.0.1:' + uiPort + '/') ? setupToken : '';
	});
	ipcMain.on('proculus:simulation', (event) => { event.returnValue = simulate; });
	app.whenReady().then(() => {
		loadSettings();
		session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
		buildMenu();
		createWindow();
	});
	app.on('window-all-closed', () => app.quit());
	app.on('before-quit', (event) => {
		if (quitting) return;
		quitting = true;
		if (server) { event.preventDefault(); stopServer().then(() => app.quit()); }
	});
	app.on('activate', () => { if (!win && app.isReady()) createWindow(); });
}
