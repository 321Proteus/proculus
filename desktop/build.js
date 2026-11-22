// Builds the desktop application for THIS platform (macOS, Linux or Windows):
//   node desktop/build.js <staged package directory> <output directory>
// The staged directory is what scripts/package.sh (or package-windows.ps1) produced: it holds the "proculus"
// program and, next to it, the libraries it needs (lib/ on Linux, the Cygwin DLLs on Windows). They are copied into
// the application, which starts the program when it is opened. Output: Proculus-<version>-<os>-<arch>.zip (macOS),
// .AppImage (Linux) or -portable.exe (Windows) in the output directory.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const [stagedArg, outArg] = process.argv.slice(2);
if (!stagedArg || !outArg) { console.error('usage: node desktop/build.js <staged package directory> <output directory>'); process.exit(2); }
const staged = path.resolve(stagedArg), outDir = path.resolve(outArg);
const here = __dirname;
const win = process.platform === 'win32';

function fail(message) { console.error('error: ' + message); process.exit(1); }
function run(command, args, options) {
	console.log('> ' + [command].concat(args).join(' '));
	const r = spawnSync(command, args, Object.assign({ cwd: here, stdio: 'inherit', shell: win }, options || {}));
	if (r.status !== 0) fail(command + ' failed (exit code ' + r.status + ')');
}

const exe = win ? 'proculus.exe' : 'proculus';
if (!fs.existsSync(path.join(staged, exe))) fail('no ' + exe + ' in ' + staged + ' (run the package script first)');

// 1. the program (and what it needs) goes into desktop/server/, from where electron-builder bundles it
const server = path.join(here, 'server');
fs.rmSync(server, { recursive: true, force: true });
fs.mkdirSync(server, { recursive: true });
for (const name of fs.readdirSync(staged)) {
	if (name === exe || name === 'lib' || name.toLowerCase().endsWith('.dll')) fs.cpSync(path.join(staged, name), path.join(server, name), { recursive: true, dereference: true });
}
console.log('bundled: ' + fs.readdirSync(server).join(', '));

// 2. dependencies (Electron and electron-builder are downloaded the first time)
if (!fs.existsSync(path.join(here, 'node_modules', 'electron-builder'))) run('npm', ['install', '--no-audit', '--no-fund']);

// 3. the application, for this platform only; unsigned
const flag = process.platform === 'darwin' ? '--mac' : win ? '--win' : '--linux';
fs.rmSync(path.join(here, 'out'), { recursive: true, force: true });
run('npx', ['electron-builder', flag, '--publish', 'never'], { env: Object.assign({}, process.env, { CSC_IDENTITY_AUTO_DISCOVERY: 'false' }) });

// 4. the finished files
fs.mkdirSync(outDir, { recursive: true });
const made = fs.readdirSync(path.join(here, 'out')).filter((f) => /\.(zip|AppImage|exe)$/.test(f) && !/blockmap/.test(f));
if (made.length === 0) fail('electron-builder produced no application file (see its messages above)');
for (const f of made) { fs.copyFileSync(path.join(here, 'out', f), path.join(outDir, f)); console.log('done: ' + path.join(outDir, f)); }
