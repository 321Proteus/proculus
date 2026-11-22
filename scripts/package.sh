#!/usr/bin/env bash
# Packs Proculus into a standalone program with its launchers and a README, as an archive in dist/.
# Every platform is built NATIVELY, on that platform:
#
#   scripts/package.sh macos      on a Mac:    third-party libraries linked in, only system libraries needed -> dist/proculus-<version>-macos-<arch>.tar.gz
#   scripts/package.sh linux      on Linux:    system libraries bundled next to the program (lib/)            -> dist/proculus-<version>-linux-<arch>.tar.gz
#   scripts/package.sh windows    in Cygwin:   (scripts/package-windows.ps1 sets that up and calls this)      -> dist/proculus-<version>-windows-<arch>.zip
#   scripts/package.sh            the one that fits this machine
#
# Each target builds in a directory of its own (build-package-<target>/), so it never disturbs your normal build/.
# Each package is smoke-tested before it is archived: the program must start on an emulated network, serve the UI and
# accept the first-run setup. Set SKIP_SMOKE=1 to skip that. The package holds one program ("proculus": API, web UI,
# simulation and command-line tools in a single file); real scans also need nmap on the PATH of the machine.
# Linux: the package runs on the distribution it was built on and on newer ones (glibc is not bundled): build it on
# the oldest distribution you want to support.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIST="${DIST:-$ROOT/dist}"
VERSION="$(sed -n 's/^project(proculus VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)"
REV="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then REV="$REV-dirty"; fi
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
SMOKE_UI_PORT="${SMOKE_UI_PORT:-18940}"
SMOKE_API_PORT="${SMOKE_API_PORT:-18941}"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is needed: $2"; }

# ---------------------------------------------------------------------------------------------------------------------
# Puts the program, launchers, README and examples into dist/<name>/ and archives it.
#   stage <name> <binary> <exe suffix> <launcher kind: sh|cmd> [extra files to put next to the program...]
stage() {
	local name="$1" binary="$2" suffix="$3" kind="$4"
	shift 4
	local dir="$DIST/proculus-$VERSION-$name"
	rm -rf "$dir"
	mkdir -p "$dir/examples"
	cp "$binary" "$dir/proculus$suffix"
	if [ -n "${EXTRA_SUBDIR:-}" ]; then mkdir -p "$dir/$EXTRA_SUBDIR"; fi
	for extra in "$@"; do cp -L "$extra" "$dir/${EXTRA_SUBDIR:+$EXTRA_SUBDIR/}"; done
	cp scripts/package/README.txt "$dir/README.txt"
	if [ "$kind" = sh ]; then
		cp scripts/package/start.sh scripts/package/start-simulation.sh "$dir/"
		chmod +x "$dir/start.sh" "$dir/start-simulation.sh" "$dir/proculus$suffix"
	else
		# Windows batch files want CRLF line endings
		for f in start.cmd start-simulation.cmd; do sed 's/$/\r/' "scripts/package/$f" > "$dir/$f"; done
	fi
	cp services/ui/examples/scan-settings.json libs/signatures/examples/minecraft.json libs/signatures/examples/custom.json "$dir/examples/"
	cp README.md "$dir/README-project.md"
	printf 'Proculus %s (%s)\nbuilt %s\n' "$VERSION" "$REV" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$dir/VERSION.txt"
	STAGED_DIR="$dir"
}

archive() { # archive <dir> tar|zip
	local dir="$1" kind="$2" base file
	base="$(basename "$dir")"
	file="$base.$([ "$kind" = zip ] && echo zip || echo tar.gz)"
	( cd "$DIST"
	  rm -f "$file"
	  if [ "$kind" = zip ]; then zip -qr "$file" "$base"; else tar -czf "$file" "$base"; fi
	  touch SHA256SUMS
	  grep -v " $file\$" SHA256SUMS > SHA256SUMS.tmp || true
	  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$file" >> SHA256SUMS.tmp; else sha256sum "$file" >> SHA256SUMS.tmp; fi
	  mv SHA256SUMS.tmp SHA256SUMS )
	ARCHIVE="$DIST/$file"
}

# Starts the packaged program on an emulated network and checks the UI, the API and the first-run setup.
#   smoke <dir> <executable name> [prefix command words, e.g. wine]
smoke() {
	[ "${SKIP_SMOKE:-0}" = 1 ] && { say "smoke test skipped (SKIP_SMOKE=1)"; return 0; }
	local dir="$1" exe="$2" store log pid token code
	need curl "used by the smoke test (or set SKIP_SMOKE=1)"
	say "smoke test: starting $exe on an emulated network"
	store="$(mktemp -d)"
	log="$store/log.txt"
	( cd "$dir" && "./$exe" serve --simulate --store "$store" --port "$SMOKE_API_PORT" --ui-port "$SMOKE_UI_PORT" >"$log" 2>&1 ) &
	pid=$!
	for _ in $(seq 1 40); do
		curl -fs "http://127.0.0.1:$SMOKE_UI_PORT/api/auth" >/dev/null 2>&1 && break
		sleep 0.25
	done
	code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$SMOKE_UI_PORT/" || true)"
	[ "$code" = 200 ] || { kill "$pid" 2>/dev/null || true; cat "$log" >&2; die "smoke test: the UI answered $code, not 200"; }
	token="$(grep -A1 'SETUP TOKEN\|setup token' "$log" | tail -1 | tr -d ' \r')"
	[ -n "$token" ] || { kill "$pid" 2>/dev/null || true; cat "$log" >&2; die "smoke test: no setup token in the output"; }
	curl -fs -X POST "http://127.0.0.1:$SMOKE_UI_PORT/api/setup" -H 'Content-Type: application/json' \
		-d "{\"setup_token\":\"$token\",\"username\":\"smoke.test\",\"password\":\"a-long-password-1\"}" | grep -q '"token"' \
		|| { kill "$pid" 2>/dev/null || true; cat "$log" >&2; die "smoke test: creating the administrator failed"; }
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	rm -rf "$store"
	say "smoke test passed: UI 200, first-run setup works"
}

# ---------------------------------------------------------------------------------------------------------------------
package_macos() {
	[ "$(uname -s)" = Darwin ] || die "the macos package must be built on a Mac"
	need cmake "install CMake"; need ninja "install Ninja"; need pkg-config "install pkg-config"
	local arch b deps
	arch="$(uname -m)"
	b="$ROOT/build-package-macos"
	deps="$b/static-deps"
	say "macOS $arch: collecting static libraries (a directory with only .a files, so the linker cannot pick a .dylib)"
	rm -rf "$deps"; mkdir -p "$deps/lib/pkgconfig"
	local dirs=(/opt/local/lib /opt/local/libexec/openssl3/lib /opt/local/lib/postgresql* /opt/homebrew/lib /opt/homebrew/opt/openssl@3/lib /opt/homebrew/opt/libpq/lib
		/usr/local/lib /usr/local/opt/openssl@3/lib /usr/local/opt/libpq/lib)
	local missing=""
	for lib in libpcre2-8 libexpat libsodium libz libssl libcrypto libpq libpgcommon libpgport; do
		local found=""
		for d in "${dirs[@]}"; do
			if [ -f "$d/$lib.a" ]; then found="$d/$lib.a"; break; fi
		done
		if [ "$lib" = libz ] && [ -z "$found" ]; then # the SDK has no static zlib on every system: the system one is fine (it is part of macOS)
			continue
		fi
		if [ -n "$found" ]; then ln -sf "$found" "$deps/lib/$lib.a"; else missing="$missing $lib"; fi
	done
	[ -z "$missing" ] || die "no static library for:$missing. MacPorts: sudo port install pcre2 expat libsodium openssl3 postgresql16 | Homebrew: brew install pcre2 expat libsodium openssl@3 libpq nlohmann-json"
	for pc in libpcre2-8 libsodium; do
		local src
		src="$(pkg-config --variable=pcfiledir "$pc" 2>/dev/null || true)/$pc.pc"
		[ -f "$src" ] || die "pkg-config does not know $pc"
		sed -E "s#^libdir=.*#libdir=$deps/lib#" "$src" > "$deps/lib/pkgconfig/$pc.pc"
	done
	local openssl_root
	openssl_root="$(cd "$(dirname "$(readlink "$deps/lib/libssl.a" 2>/dev/null || echo "$deps/lib/libssl.a")")/.." && pwd)"
	say "configuring (Release)"
	PKG_CONFIG_PATH="$deps/lib/pkgconfig" cmake -S . -B "$b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DPROCULUS_REQUIRE_DB=ON \
		-DCMAKE_LIBRARY_PATH="$deps/lib" -DOPENSSL_ROOT_DIR="$openssl_root" -DOPENSSL_USE_STATIC_LIBS=ON \
		-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
		-DCMAKE_CXX_STANDARD_LIBRARIES="-L$deps/lib -lpgcommon -lpgport -lssl -lcrypto -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv -lz" >/dev/null
	say "building (this takes a few minutes)"
	cmake --build "$b" --target gateway --parallel "$JOBS" 2>&1 | grep -v "warning: object file" | tail -3
	local bin="$b/services/gateway/gateway"
	[ -x "$bin" ] || die "the build did not produce $bin"
	strip -x "$bin" 2>/dev/null || true
	say "checking that only system libraries are needed"
	local bad
	bad="$(otool -L "$bin" | tail -n +2 | awk '{print $1}' | grep -v '^/usr/lib/\|^/System/' || true)"
	[ -z "$bad" ] || die "the binary still depends on libraries that are not part of macOS: $bad"
	otool -L "$bin" | tail -n +2 | awk '{print "    " $1}'
	mkdir -p "$DIST"
	stage "macos-$arch" "$bin" "" sh
	smoke "$STAGED_DIR" proculus
	archive "$STAGED_DIR" tar
	say "done: $ARCHIVE"
}

package_linux() {
	[ "$(uname -s)" = Linux ] || die "the linux package must be built on Linux"
	local m missing=""
	for c in cmake ninja pkg-config g++ readelf ldd tar; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
	[ -z "$missing" ] || die "missing tools:$missing. Debian/Ubuntu: sudo apt install build-essential cmake ninja-build pkg-config binutils nlohmann-json3-dev libssl-dev libsodium-dev libpq-dev libpcre2-dev libexpat1-dev zlib1g-dev curl"
	for m in libpcre2-8 libsodium libpq expat openssl; do pkg-config --exists "$m" 2>/dev/null || missing="$missing $m"; done
	[ -z "$missing" ] || die "missing development libraries (pkg-config cannot find:$missing). Debian/Ubuntu: sudo apt install nlohmann-json3-dev libssl-dev libsodium-dev libpq-dev libpcre2-dev libexpat1-dev zlib1g-dev | Fedora: sudo dnf install json-devel openssl-devel libsodium-devel libpq-devel pcre2-devel expat-devel zlib-devel"
	local b="$ROOT/build-package-linux" arch
	arch="$(uname -m)"
	say "Linux $arch: configuring (Release)"
	# libstdc++ and libgcc are linked in; the other libraries are bundled below. --disable-new-dtags makes the $ORIGIN/lib
	# search path an RPATH, which (unlike RUNPATH) also applies to the bundled libraries' own dependencies.
	cmake -S . -B "$b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DPROCULUS_REQUIRE_DB=ON \
		-DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc -Wl,--disable-new-dtags -Wl,-rpath,'\$ORIGIN/lib'" 2>&1 | tail -5
	say "building (this takes a few minutes)"
	cmake --build "$b" --target gateway --parallel "$JOBS" 2>&1 | tail -3
	local bin="$b/services/gateway/gateway"
	[ -x "$bin" ] || die "the build did not produce $bin (see the messages above)"
	strip "$bin" 2>/dev/null || true
	readelf -d "$bin" | grep -q "R.*PATH.*ORIGIN" || die "the program has no \$ORIGIN/lib search path; the bundled libraries would not be found"
	say "bundling the shared libraries the program needs (everything except the C library, which every Linux has)"
	# the C library, the loader and the kernel's vdso are never bundled; everything else ldd resolves (also indirect dependencies) is
	local libs=()
	while IFS= read -r so; do libs+=("$so"); done < <(ldd "$bin" | awk '/=>/ {print $3}' | grep '^/' \
		| grep -Ev '/(ld-linux[^/]*|libc\.so[^/]*|libm\.so[^/]*|libpthread\.so[^/]*|libdl\.so[^/]*|librt\.so[^/]*|libutil\.so[^/]*|libresolv\.so[^/]*|libnsl\.so[^/]*|libanl\.so[^/]*)$' | sort -u)
	if [ "${#libs[@]}" -gt 0 ]; then printf '    %s\n' "${libs[@]##*/}"; else echo "    (none)"; fi
	mkdir -p "$DIST"
	EXTRA_SUBDIR=lib stage "linux-$arch" "$bin" "" sh "${libs[@]}"
	EXTRA_SUBDIR=
	[ "${#libs[@]}" -gt 0 ] || rmdir "$STAGED_DIR/lib" 2>/dev/null || true
	smoke "$STAGED_DIR" proculus
	archive "$STAGED_DIR" tar
	say "done: $ARCHIVE"
}

package_windows() {
	case "$(uname -s)" in CYGWIN*|MSYS*|MINGW*) ;; *) die "the windows package is built inside Cygwin: run scripts/package-windows.ps1 on a Windows machine" ;; esac
	need cmake "install it in Cygwin"; need ninja "install it in Cygwin"; need zip "install it in Cygwin"; need pkg-config "install it in Cygwin"
	local b="$ROOT/build-package-windows" arch
	arch="$(uname -m)"
	local m missing=""
	for m in libpcre2-8 libsodium libpq expat openssl; do pkg-config --exists "$m" 2>/dev/null || missing="$missing $m"; done
	[ -z "$missing" ] || die "Cygwin is missing the development packages for:$missing (re-run scripts/package-windows.ps1 without -SkipInstall, or install libpcre2-devel libsodium-devel libpq-devel libexpat-devel libssl-devel with Cygwin's setup)"
	# nlohmann-json is a header-only library that Cygwin may not offer: fetch it if CMake cannot find it
	local prefix="$ROOT/build-package-windows/deps" nlohmann_args=()
	if ! echo 'find_package(nlohmann_json 3.11 REQUIRED)' > /tmp/nl-probe.cmake || ! cmake -P /tmp/nl-probe.cmake >/dev/null 2>&1; then
		if [ ! -f "$prefix/share/cmake/nlohmann_json/nlohmann_jsonConfig.cmake" ]; then
			say "fetching nlohmann/json 3.11.3 (header-only)"
			need git "install it in Cygwin"
			rm -rf "$prefix-src"; git clone --quiet --depth 1 --branch v3.11.3 https://github.com/nlohmann/json "$prefix-src"
			cmake -S "$prefix-src" -B "$prefix-src/build" -G Ninja -DJSON_BuildTests=OFF -DCMAKE_INSTALL_PREFIX="$prefix" >/dev/null
			cmake --install "$prefix-src/build" >/dev/null
		fi
		nlohmann_args=(-DCMAKE_PREFIX_PATH="$prefix")
	fi
	say "configuring (Release)"
	# -D_GNU_SOURCE: in strict C11/C++17 mode Cygwin hides POSIX declarations that glibc shows (fork, strdup, ...)
	cmake -S . -B "$b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DPROCULUS_REQUIRE_DB=ON \
		-DCMAKE_C_FLAGS=-D_GNU_SOURCE -DCMAKE_CXX_FLAGS=-D_GNU_SOURCE "${nlohmann_args[@]}" 2>&1 | tail -15
	say "building (this takes a few minutes)"
	cmake --build "$b" --target gateway --parallel "$JOBS" 2>&1 | tail -15
	local bin="$b/services/gateway/gateway.exe"
	[ -f "$bin" ] || bin="$b/services/gateway/gateway"
	[ -f "$bin" ] || die "the build did not produce the program (see the messages above)"
	strip "$bin" 2>/dev/null || true
	say "collecting the Cygwin libraries the program needs (they go next to it)"
	local dlls=()
	while IFS= read -r dll; do dlls+=("$dll"); done < <(ldd "$bin" | awk '/=>/ {print $3}' | grep -iv '^/cygdrive/\|/windows/\|/system32/' | sort -u)
	printf '    %s\n' "${dlls[@]##*/}"
	mkdir -p "$DIST"
	stage "windows-$arch" "$bin" ".exe" cmd "${dlls[@]}"
	smoke "$STAGED_DIR" proculus.exe
	archive "$STAGED_DIR" zip
	say "done: $ARCHIVE"
}

# ---------------------------------------------------------------------------------------------------------------------
target="${1:-auto}"
if [ "$target" = auto ]; then
	case "$(uname -s)" in Darwin) target=macos ;; CYGWIN*|MSYS*|MINGW*) target=windows ;; *) target=linux ;; esac
fi
case "$target" in
	macos) package_macos ;;
	linux) package_linux ;;
	windows) package_windows ;;
	-h|--help|help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
	*) die "unknown target '$target' (macos, linux, windows)" ;;
esac
