#!/usr/bin/env python3
"""
PROCULUS — Attack Surface Intelligence (CBI AGH Edition v3.0)
Pełnoprawna aplikacja desktopowa (.exe / natywne okno bez przeglądarki) do cyklicznego
discovery scanu rozległych sieci (>10 000 adresów IP), analizy usług HTTP/HTTPS/TLS,
wykrywania zmian w czasie (Diff), obsługi niestabilnych hostów, RBAC, szyfrowania
At-Rest oraz integracji z DefectDojo.
"""

import os
import sys
import re
import io
import csv
import ssl
import json
import time
import hmac
import base64
import socket
import shutil
import hashlib
import sqlite3
import secrets
import ipaddress
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, time as dtime
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# ==============================================================================
# ŚCIEŻKI APLIKACJI (OBSŁUGA TRYBU .EXE PYINSTALLER ORAZ SKRYPTU PYTHON)
# ==============================================================================

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = getattr(sys, "_MEIPASS", APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR

DB_FILE = os.path.join(APP_DIR, "proculus_vault.db")
KEY_FILE = os.path.join(APP_DIR, "proculus_master.key")
ICON_ICO_PATH = os.path.join(BUNDLE_DIR, "proculus.ico")
ICON_PNG_PATH = os.path.join(BUNDLE_DIR, "proculus.png")
HOST_BIND = "127.0.0.1"


def find_free_port(preferred: int = 8765) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST_BIND, preferred))
            return preferred
        except OSError:
            s.bind((HOST_BIND, 0))
            return s.getsockname()[1]


# ==============================================================================
# SZYFROWANIE W SPOCZYNKU (AUTHENTICATED ENCRYPTION AT REST: CTR + HMAC-SHA256)
# ==============================================================================

def load_or_create_master_key() -> bytes:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    try:
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    return key


MASTER_KEY = load_or_create_master_key()


class AtRestCipher:
    """Szyfrowanie uwierzytelnione (CTR + HMAC-SHA256) dla pól wrażliwych w SQLite."""

    @staticmethod
    def _keystream(nonce: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hmac.new(MASTER_KEY, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if plaintext is None:
            return ""
        raw = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(16)
        ks = cls._keystream(nonce, len(raw))
        ct = bytes(a ^ b for a, b in zip(raw, ks))
        tag = hmac.new(MASTER_KEY, nonce + ct, hashlib.sha256).digest()
        return "ENCv1:" + base64.b64encode(nonce + tag + ct).decode("ascii")

    @classmethod
    def decrypt(cls, token: str) -> str:
        if not token or not token.startswith("ENCv1:"):
            return token or ""
        blob = base64.b64decode(token[6:])
        nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
        expected = hmac.new(MASTER_KEY, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Naruszenie integralności zaszyfrowanych danych!")
        ks = cls._keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8")


# ==============================================================================
# AUTODETEKCJA SIECI LOKALNEJ UŻYTKOWNIKA (WINDOWS / LINUX)
# ==============================================================================

def detect_local_network_presets() -> dict:
    """
    Automatycznie wykrywa interfejsy IP komputera i buduje bezpieczne
    presety sieciowe (CIDR /24, brama domyślna, host lokalny, test >10k IP).
    """
    detected_ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip_s = info[4][0]
            if not ip_s.startswith("127.") and not ip_s.startswith("169.254.") and ip_s not in detected_ips:
                detected_ips.append(ip_s)
    except Exception:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            if primary_ip and not primary_ip.startswith("127.") and not primary_ip.startswith("169.254."):
                if primary_ip in detected_ips:
                    detected_ips.remove(primary_ip)
                detected_ips.insert(0, primary_ip)
    except Exception:
        pass

    presets = []
    primary = detected_ips[0] if detected_ips else "192.168.1.10"

    for ip_s in detected_ips:
        net24 = str(ipaddress.ip_network(f"{ip_s}/24", strict=False))
        gw_ip = str(ipaddress.ip_network(f"{ip_s}/24", strict=False).network_address + 1)
        presets.append({
            "value": net24,
            "hosts_count": 254,
            "label": f"Cała Twoja sieć lokalna ({net24} — 254 hosty)",
            "desc": f"Wykryto na tym komputerze adres {ip_s}. Skanuje wszystkie urządzenia w lokalnej podsieci /24."
        })
        presets.append({
            "value": gw_ip,
            "hosts_count": 1,
            "label": f"Tylko brama / router sieciowy ({gw_ip} — 1 host)",
            "desc": f"Szybki test pojedynczego urządzenia brzegowego ({gw_ip}) w Twojej sieci lokalnej."
        })
        presets.append({
            "value": ip_s,
            "hosts_count": 1,
            "label": f"Tylko ten komputer ({ip_s} — 1 host)",
            "desc": "Skanuje wyłącznie otwarte usługi i porty na Twoim własnym komputerze."
        })

    presets.append({
        "value": "127.0.0.1",
        "hosts_count": 1,
        "label": "Localhost / Pętla zwrotna (127.0.0.1 — 1 host)",
        "desc": "Bezpieczny autotest lokalnych usług działających na interfejsie loopback."
    })

    net16 = str(ipaddress.ip_network(f"{primary}/16", strict=False))
    presets.append({
        "value": net16,
        "hosts_count": 65534,
        "label": f"Rozległa sieć uczelniana/korporacyjna ({net16} — 65 534 IP)",
        "desc": "Tryb dla dużych sieci (>10 000 IP) z automatycznym podziałem na podgrupy."
    })

    presets.append({
        "value": "__CUSTOM__",
        "hosts_count": 1,
        "label": "✎ Wpisz własny adres IP, maskę CIDR lub domenę ręcznie...",
        "desc": "Odblokowuje pole tekstowe, w którym możesz wpisać dowolny zakres, np. 10.0.0.0/22 lub agh.edu.pl."
    })

    return {
        "primary_ip": primary,
        "all_ips": detected_ips,
        "presets": presets
    }


# ==============================================================================
# WARSTWA BAZY DANYCH I ROLE RBAC
# ==============================================================================

ROLES = {
    "Administracja": {"read": True, "modify": True, "add_delete": True, "admin": True},
    "Dodawanie, usuwanie, modyfikacja": {"read": True, "modify": True, "add_delete": True, "admin": False},
    "Modyfikacja i odczyt": {"read": True, "modify": True, "add_delete": False, "admin": False},
    "Odczyt": {"read": True, "modify": False, "add_delete": False, "admin": False},
}

db_lock = threading.RLock()


def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock:
        conn = get_db()
        cur = conn.cursor()

        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_enc TEXT NOT NULL,
            label TEXT,
            tags TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            match_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_sec REAL DEFAULT 0,
            status TEXT NOT NULL,
            mode TEXT NOT NULL,
            total_ips INTEGER DEFAULT 0,
            scanned_ips INTEGER DEFAULT 0,
            active_hosts INTEGER DEFAULT 0,
            summary_json TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_enc TEXT NOT NULL,
            ip_hash TEXT NOT NULL,
            hostname_enc TEXT,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT,
            http_status INTEGER,
            http_title_enc TEXT,
            headers_enc TEXT,
            cookies_enc TEXT,
            tls_info_enc TEXT,
            redirect_enc TEXT,
            technologies TEXT,
            environment_tag TEXT,
            matched_signatures TEXT,
            confidence INTEGER DEFAULT 80,
            analyst_notes_enc TEXT DEFAULT '',
            custom_status TEXT DEFAULT 'ACTIVE',
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS host_overrides (
            ip_hash TEXT PRIMARY KEY,
            ip_enc TEXT NOT NULL,
            custom_hostname_enc TEXT,
            custom_env TEXT,
            custom_tags TEXT,
            analyst_notes_enc TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS host_stability (
            ip_hash TEXT PRIMARY KEY,
            ip_enc TEXT NOT NULL,
            seen_count INTEGER DEFAULT 0,
            missed_streak INTEGER DEFAULT 0,
            last_seen TEXT,
            state TEXT DEFAULT 'ONLINE'
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            interval_minutes INTEGER DEFAULT 120,
            window_start TEXT DEFAULT '00:00',
            window_end TEXT DEFAULT '23:59',
            mode TEXT DEFAULT 'balanced',
            rate_limit INTEGER DEFAULT 150,
            chunk_size INTEGER DEFAULT 64,
            offline_threshold INTEGER DEFAULT 3,
            enabled INTEGER DEFAULT 0,
            last_run TEXT
        );
        """)

        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            default_users = [
                ("admin", "admin123", "Administracja"),
                ("operator", "oper123", "Dodawanie, usuwanie, modyfikacja"),
                ("analyst", "anal123", "Modyfikacja i odczyt"),
                ("viewer", "view123", "Odczyt"),
            ]
            for u, p, r in default_users:
                salt = secrets.token_hex(16)
                ph = hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100_000).hex()
                cur.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)", (u, ph, salt, r))

        cur.execute("SELECT COUNT(*) FROM signatures")
        if cur.fetchone()[0] == 0:
            default_sigs = [
                ("WordPress CMS", "CMS", "html", "wp-content|wp-includes|WordPress", "INFO"),
                ("Joomla! CMS", "CMS", "html", "Joomla!|/media/system/js/", "INFO"),
                ("Drupal CMS", "CMS", "header", "X-Generator: Drupal|X-Drupal-Cache", "INFO"),
                ("PHP Session Cookie", "Framework", "cookie", "PHPSESSID", "INFO"),
                ("Spring Boot / Java", "Framework", "cookie", "JSESSIONID", "INFO"),
                ("ASP.NET Framework", "Framework", "header", "X-AspNet-Version|ASP\\.NET", "INFO"),
                ("Apache Tomcat", "Serwer aplikacyjny", "html", "Apache Tomcat", "LOW"),
                ("Nginx Server", "Serwer aplikacyjny", "header", "Server: nginx", "INFO"),
                ("Panel Administracyjny", "Panel Admina", "path_probe", "/admin|/login", "MEDIUM"),
                ("Środowisko Testowe / Staging", "Środowisko", "title_or_host", "staging|dev|test|uat|sandbox|preprod", "MEDIUM"),
                ("Urządzenie IoT / Router", "IoT", "html", "IP Camera|Hikvision|MikroTik|RouterOS|Dahua|NETGEAR", "MEDIUM"),
                ("Wersja / Debug w stopce", "Konfiguracja", "html", "Powered by|Version [0-9]+\\.[0-9]+|Debug mode", "LOW"),
            ]
            cur.executemany(
                "INSERT INTO signatures (name, category, match_type, pattern, severity) VALUES (?, ?, ?, ?, ?)",
                default_sigs
            )

        cur.execute("SELECT COUNT(*) FROM schedules")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO schedules (name, interval_minutes, window_start, window_end, mode, rate_limit, chunk_size, offline_threshold, enabled)
                VALUES ('Skan cykliczny Proculus CBI AGH', 120, '00:00', '23:59', 'balanced', 150, 64, 3, 0)
            """)

        cur.execute("SELECT COUNT(*) FROM targets")
        if cur.fetchone()[0] == 0:
            net_info = detect_local_network_presets()
            default_cidr = net_info["presets"][0]["value"] if net_info["presets"] else "127.0.0.1"
            now = datetime.now().isoformat(timespec="seconds")
            cur.execute("INSERT INTO targets (target_enc, label, tags, created_at) VALUES (?, ?, ?, ?)",
                        (AtRestCipher.encrypt(default_cidr), "Wykryta sieć lokalna", "lan,auto", now))

        conn.commit()
        conn.close()


def ip_digest(ip_str: str) -> str:
    return hmac.new(MASTER_KEY, ip_str.encode("utf-8"), hashlib.sha256).hexdigest()


# ==============================================================================
# SILNIK SKANOWANIA DISCOVERY, HTTP/TLS/FAVICON FINGERPRINTING I TELEMETRIA
# ==============================================================================

SCAN_MODES = {
    "fast": {
        "name": "Szybki Discovery (5 głównych portów)",
        "ports": [22, 80, 443, 8080, 8443],
        "timeout": 0.45,
        "probe_paths": False,
        "use_nmap": False
    },
    "balanced": {
        "name": "Zbalansowany (17 usług + HTTP/TLS + Sygnatury)",
        "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443, 9000],
        "timeout": 0.75,
        "probe_paths": True,
        "use_nmap": True
    },
    "deep": {
        "name": "Głęboki Recon (34 porty + Nmap -sV + Ścieżki)",
        "ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049,
                  3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017],
        "timeout": 1.1,
        "probe_paths": True,
        "use_nmap": True
    },
    "stealth": {
        "name": "Ostrożny / Low-Noise (4 porty web, niski ruch)",
        "ports": [80, 443, 8080, 8443],
        "timeout": 0.9,
        "probe_paths": False,
        "use_nmap": False
    }
}

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5000: "http-alt",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8008: "http",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "sonarqube/php-fpm", 9090: "prometheus/web", 9200: "elasticsearch", 27017: "mongodb"
}


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.interval = 1.0 / max(1.0, float(rate_per_sec))
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                sleep_for = self.next_time - now
                self.next_time += self.interval
            else:
                sleep_for = 0.0
                self.next_time = now + self.interval
        if sleep_for > 0:
            time.sleep(sleep_for)


class ScanManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.stop_requested = False
        self.current_scan_id = None
        self.progress = {
            "running": False,
            "scan_id": None,
            "mode": "",
            "mode_ports": [],
            "target_label": "",
            "total_ips": 0,
            "scanned_ips": 0,
            "total_probes": 0,
            "completed_probes": 0,
            "active_hosts": 0,
            "findings_count": 0,
            "current_chunk": 0,
            "total_chunks": 0,
            "current_stage": 0,
            "stage_label": "Oczekiwanie na uruchomienie",
            "current_ip": "-",
            "current_port": 0,
            "current_service": "-",
            "live_hosts": [],
            "elapsed_sec": 0.0,
            "eta_sec": 0.0,
            "ips_per_sec": 0.0,
            "probes_per_sec": 0.0,
            "status_text": "Gotowy do skanowania",
            "last_summary": None,
            "logs": []
        }

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        with self.lock:
            self.progress["logs"].append(line)
            if len(self.progress["logs"]) > 120:
                self.progress["logs"] = self.progress["logs"][-120:]

    def _update_live_host_telemetry(self, ip: str, state: str, current_port: int = 0, open_port: int = 0, service: str = ""):
        with self.lock:
            hosts = self.progress["live_hosts"]
            entry = None
            for h in hosts:
                if h["ip"] == ip:
                    entry = h
                    break
            if entry is None:
                entry = {"ip": ip, "state": state, "current_port": current_port, "open_ports": [], "scanned_ports": []}
                hosts.append(entry)
                if len(hosts) > 8:
                    del hosts[0]
            entry["state"] = state
            if current_port:
                entry["current_port"] = current_port
                if current_port not in entry["scanned_ports"]:
                    entry["scanned_ports"].append(current_port)
            if open_port:
                label = f"{open_port}/{service}" if service else str(open_port)
                if not any(x["port"] == open_port for x in entry["open_ports"]):
                    entry["open_ports"].append({"port": open_port, "service": service or COMMON_SERVICES.get(open_port, "tcp"), "label": label})

    def expand_targets(self, raw_targets: list) -> list:
        resolved = []
        seen = set()
        for item in raw_targets:
            item = item.strip()
            if not item:
                continue
            try:
                if "/" in item:
                    net = ipaddress.ip_network(item, strict=False)
                    hosts_iter = net.hosts() if net.num_addresses > 2 else [net.network_address]
                    for ip_obj in hosts_iter:
                        s = str(ip_obj)
                        if s not in seen:
                            seen.add(s)
                            resolved.append((s, ""))
                elif "-" in item and not any(c.isalpha() for c in item):
                    start_s, end_s = item.split("-", 1)
                    start_ip = int(ipaddress.ip_address(start_s.strip()))
                    end_ip = int(ipaddress.ip_address(end_s.strip()))
                    for ip_int in range(min(start_ip, end_ip), max(start_ip, end_ip) + 1):
                        s = str(ipaddress.ip_address(ip_int))
                        if s not in seen:
                            seen.add(s)
                            resolved.append((s, ""))
                else:
                    try:
                        ipaddress.ip_address(item)
                        if item not in seen:
                            seen.add(item)
                            resolved.append((item, ""))
                    except ValueError:
                        infos = socket.getaddrinfo(item, None)
                        for info in infos:
                            ip_s = info[4][0]
                            if ":" not in ip_s and (ip_s, item) not in seen:
                                seen.add((ip_s, item))
                                resolved.append((ip_s, item))
                                break
            except Exception as e:
                self.log(f"Pominięto nieprawidłowy cel '{item}': {e}")
        return resolved

    def _within_window(self, win_start: str, win_end: str) -> bool:
        if not win_start or not win_end:
            return True
        try:
            now_t = datetime.now().time()
            sh, sm = map(int, win_start.split(":"))
            eh, em = map(int, win_end.split(":"))
            t_start = dtime(sh, sm)
            t_end = dtime(eh, em)
            if t_start <= t_end:
                return t_start <= now_t <= t_end
            return now_t >= t_start or now_t <= t_end
        except Exception:
            return True

    def _fast_ptr_lookup(self, ip: str, timeout: float = 0.2) -> str:
        res = [""]
        def _resolve():
            try:
                res[0] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        t = threading.Thread(target=_resolve, daemon=True)
        t.start()
        t.join(timeout)
        return res[0]

    def _fetch_tls_info(self, ip: str, port: int, hostname: str, timeout: float) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni = hostname if hostname else ip
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=sni) as ssock:
                    ver = ssock.version() or "TLS"
                    cipher = ssock.cipher()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    fp = hashlib.sha256(cert_bin).hexdigest()[:16] if cert_bin else "brak"
                    return f"{ver} | Cipher: {cipher[0] if cipher else '?'} | SHA256:{fp}"
        except Exception:
            return ""

    def _probe_http(self, ip: str, port: int, hostname: str, use_tls: bool, timeout: float, probe_paths: bool):
        scheme = "https" if use_tls else "http"
        host_hdr = hostname if hostname else ip
        url = f"{scheme}://{ip}:{port}/"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, headers={
            "Host": host_hdr,
            "User-Agent": "Proculus-Discovery-Scanner/3.0 (CBI-AGH Safe Recon)"
        })

        status = 0
        headers_dict = {}
        cookies = []
        redirect_to = ""
        body = ""

        try:
            resp = opener.open(req, timeout=timeout)
            status = resp.getcode()
            headers_dict = dict(resp.headers.items())
            cookies = resp.headers.get_all("Set-Cookie") or []
            body = resp.read(32768).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status = e.code
            headers_dict = dict(e.headers.items()) if e.headers else {}
            cookies = e.headers.get_all("Set-Cookie") or [] if e.headers else []
            redirect_to = headers_dict.get("Location", "")
            try:
                body = e.read(16384).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except Exception:
            return None

        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""

        favicon_hash = ""
        try:
            freq = urllib.request.Request(
                f"{scheme}://{ip}:{port}/favicon.ico",
                headers={"Host": host_hdr, "User-Agent": "Proculus-Discovery-Scanner/3.0"}
            )
            fresp = opener.open(freq, timeout=min(0.45, timeout))
            fav_bytes = fresp.read(16384)
            if fav_bytes:
                favicon_hash = hashlib.sha256(fav_bytes).hexdigest()[:16]
        except Exception:
            pass

        found_paths = []
        if probe_paths:
            for p in ("/login", "/admin", "/version"):
                try:
                    preq = urllib.request.Request(
                        f"{scheme}://{ip}:{port}{p}",
                        method="HEAD",
                        headers={"Host": host_hdr, "User-Agent": "Proculus-Discovery-Scanner/3.0"}
                    )
                    presp = opener.open(preq, timeout=min(0.6, timeout))
                    if presp.getcode() in (200, 401, 403):
                        found_paths.append(f"{p}({presp.getcode()})")
                except urllib.error.HTTPError as he:
                    if he.code in (401, 403):
                        found_paths.append(f"{p}({he.code})")
                except Exception:
                    pass

        tls_info = self._fetch_tls_info(ip, port, hostname, timeout) if use_tls else ""

        return {
            "status": status,
            "title": title[:200],
            "headers": headers_dict,
            "cookies": cookies,
            "redirect": redirect_to,
            "tls": tls_info,
            "favicon_hash": favicon_hash,
            "body": body,
            "paths": found_paths
        }

    def _run_nmap_chunk(self, ips: list, ports: list) -> dict:
        if not shutil.which("nmap") or not ips:
            return {}
        port_arg = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-Pn", "-n", "-sT", "-sV", "--version-light", "-T4", "-p", port_arg, "-oX", "-"] + ips
        parsed = {}
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if proc.returncode == 0 and proc.stdout.strip():
                root = ET.fromstring(proc.stdout)
                for host_el in root.findall("host"):
                    addr_el = host_el.find("address")
                    if addr_el is None:
                        continue
                    ip_addr = addr_el.attrib.get("addr", "")
                    parsed[ip_addr] = {}
                    for port_el in host_el.findall(".//port"):
                        st = port_el.find("state")
                        if st is not None and st.attrib.get("state") == "open":
                            p_num = int(port_el.attrib.get("portid", 0))
                            srv_el = port_el.find("service")
                            srv_name = ""
                            if srv_el is not None:
                                srv_name = f"{srv_el.attrib.get('name', '')} {srv_el.attrib.get('product', '')} {srv_el.attrib.get('version', '')}".strip()
                            parsed[ip_addr][p_num] = srv_name
        except Exception:
            pass
        return parsed

    def _evaluate_signatures_and_tech(self, host_ip: str, hostname: str, port: int, service: str, http_data: dict, signatures: list):
        techs = set()
        matched_sigs = []
        env_tag = "PROD/STANDARD"
        confidence = 70

        if service:
            techs.add(service.split()[0])

        headers_str = ""
        cookies_str = ""
        body_str = ""
        title_str = ""
        paths_str = ""
        fav_str = ""

        if http_data:
            confidence = 90
            headers_str = "\n".join(f"{k}: {v}" for k, v in http_data["headers"].items())
            cookies_str = "\n".join(http_data["cookies"])
            body_str = http_data["body"]
            title_str = http_data["title"]
            paths_str = " ".join(http_data["paths"])
            fav_str = http_data.get("favicon_hash", "")

            srv_hdr = http_data["headers"].get("Server", "")
            xpb_hdr = http_data["headers"].get("X-Powered-By", "")
            if srv_hdr:
                techs.add(srv_hdr)
            if xpb_hdr:
                techs.add(xpb_hdr)
            if fav_str:
                techs.add(f"Favicon:{fav_str}")

            combined_meta = f"{hostname} {title_str} {headers_str}".lower()
            if any(w in combined_meta for w in ("staging", "dev.", "-dev", "test.", "-test", "uat", "sandbox", "preprod")):
                env_tag = "STAGING / TEST"

            if any(w in combined_meta for w in ("admin", "panel", "dashboard", "logowanie", "sign in", "wp-login", "routeros", "mikrotik")) or http_data["paths"]:
                env_tag = "PANEL ADMINA" if env_tag == "PROD/STANDARD" else env_tag + " + PANEL ADMINA"

        for sig in signatures:
            if not sig["enabled"]:
                continue
            mtype = sig["match_type"]
            pat = sig["pattern"]
            haystack = ""
            if mtype == "header":
                haystack = headers_str
            elif mtype == "cookie":
                haystack = cookies_str
            elif mtype == "html":
                haystack = body_str
            elif mtype == "title_or_host":
                haystack = f"{hostname} {title_str}"
            elif mtype == "path_probe":
                haystack = paths_str
            elif mtype == "favicon_hash":
                haystack = fav_str
            elif mtype == "service":
                haystack = service

            if haystack and re.search(pat, haystack, re.IGNORECASE):
                matched_sigs.append(f"[{sig['severity']}] {sig['name']}")
                techs.add(f"{sig['category']}: {sig['name']}")
                confidence = min(99, confidence + 5)

        return sorted(techs), env_tag, matched_sigs, confidence

    def start_scan(self, mode="balanced", rate_limit=150, chunk_size=64, win_start="00:00", win_end="23:59",
                   max_duration_sec=3600, offline_threshold=3, custom_targets=None):
        with self.lock:
            if self.running:
                return False, "Skanowanie jest już w toku."
            self.running = True
            self.stop_requested = False

        t = threading.Thread(
            target=self._worker,
            args=(mode, rate_limit, chunk_size, win_start, win_end, max_duration_sec, offline_threshold, custom_targets),
            daemon=True
        )
        t.start()
        return True, "Rozpoczęto skanowanie."

    def stop_scan(self):
        with self.lock:
            if self.running:
                self.stop_requested = True
                return True
        return False

    def clear_live_status(self):
        with self.lock:
            if not self.running:
                self.progress.update({
                    "scan_id": None,
                    "total_ips": 0,
                    "scanned_ips": 0,
                    "total_probes": 0,
                    "completed_probes": 0,
                    "active_hosts": 0,
                    "findings_count": 0,
                    "current_chunk": 0,
                    "total_chunks": 0,
                    "current_stage": 0,
                    "stage_label": "Oczekiwanie na uruchomienie",
                    "current_ip": "-",
                    "current_port": 0,
                    "current_service": "-",
                    "live_hosts": [],
                    "elapsed_sec": 0.0,
                    "eta_sec": 0.0,
                    "ips_per_sec": 0.0,
                    "probes_per_sec": 0.0,
                    "status_text": "Gotowy do nowego skanu",
                    "last_summary": None,
                    "logs": []
                })

    def _worker(self, mode, rate_limit, chunk_size, win_start, win_end, max_duration_sec, offline_threshold, custom_targets):
        t_start = time.monotonic()
        started_iso = datetime.now().isoformat(timespec="seconds")
        mode_cfg = SCAN_MODES.get(mode, SCAN_MODES["balanced"])
        ports_list = mode_cfg["ports"]

        with db_lock:
            conn = get_db()
            cur = conn.cursor()
            if custom_targets is None:
                cur.execute("SELECT target_enc FROM targets")
                raw_targets = [AtRestCipher.decrypt(r["target_enc"]) for r in cur.fetchall()]
            else:
                raw_targets = custom_targets

            cur.execute("SELECT * FROM signatures WHERE enabled = 1")
            signatures = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM host_overrides")
            overrides = {r["ip_hash"]: dict(r) for r in cur.fetchall()}

            cur.execute("INSERT INTO scans (started_at, status, mode) VALUES (?, 'RUNNING', ?)", (started_iso, mode))
            scan_id = cur.lastrowid
            conn.commit()
            conn.close()

        self.current_scan_id = scan_id
        target_label = ", ".join(raw_targets) if raw_targets else "Brak"

        with self.lock:
            self.progress.update({
                "running": True,
                "scan_id": scan_id,
                "mode": mode,
                "mode_ports": ports_list,
                "target_label": target_label,
                "current_stage": 1,
                "stage_label": "Etap 1/4: Discovery celów i podział na podgrupy",
                "live_hosts": [],
                "completed_probes": 0,
                "total_probes": 1,
                "last_summary": None,
                "status_text": "Etap 1/4: Rozwiązywanie adresów IP i podział na podgrupy..."
            })

        self.log(f"[ETAP 1/4] Start skanu #{scan_id} | Cel: {target_label} | Tryb: {mode_cfg['name']}")

        targets_expanded = self.expand_targets(raw_targets)
        total_ips = len(targets_expanded)
        chunk_size = max(16, int(chunk_size))
        chunks = [targets_expanded[i:i + chunk_size] for i in range(0, total_ips, chunk_size)]
        total_probes = max(1, total_ips * len(ports_list))

        with self.lock:
            self.progress.update({
                "total_ips": total_ips,
                "scanned_ips": 0,
                "total_probes": total_probes,
                "completed_probes": 0,
                "active_hosts": 0,
                "findings_count": 0,
                "current_chunk": 0,
                "total_chunks": len(chunks),
                "current_stage": 2,
                "stage_label": "Etap 2/4: Sondowanie portów TCP",
                "elapsed_sec": 0.0,
                "ips_per_sec": 0.0,
                "probes_per_sec": 0.0,
                "status_text": f"Skanowanie {total_ips} hostów ({len(chunks)} podgrup, {total_probes} sond)..."
            })

        self.log(f"[SPLIT] Podzielono {total_ips} adresów IP na {len(chunks)} podgrup po max {chunk_size} hostów.")
        limiter = RateLimiter(rate_limit)
        active_ip_hashes = set()
        all_scan_findings = []
        scanned_count = 0
        completed_probes = 0
        probe_counter_lock = threading.Lock()
        status_final = "COMPLETED"
        workers = min(64, max(8, int(rate_limit // 2)))

        for c_idx, chunk in enumerate(chunks, start=1):
            if not self._within_window(win_start, win_end):
                self.log(f"[WINDOW] Przekroczono okno czasowe ({win_start}-{win_end}). Zatrzymywanie skanu.")
                status_final = "PAUSED_WINDOW"
                break

            if (time.monotonic() - t_start) > max_duration_sec:
                self.log(f"[TIMEOUT] Przekroczono maksymalny czas skanu ({max_duration_sec}s).")
                status_final = "TIMEOUT_WINDOW"
                break

            if self.stop_requested:
                self.log("[ABORT] Skanowanie przerwane przez operatora.")
                status_final = "STOPPED"
                break

            with self.lock:
                self.progress["current_chunk"] = c_idx
                self.progress["current_stage"] = 2
                self.progress["stage_label"] = f"Etap 2/4: Skan portów (Podgrupa {c_idx}/{len(chunks)})"
                self.progress["status_text"] = f"Skanowanie podgrupy {c_idx}/{len(chunks)}..."

            nmap_map = {}
            if mode_cfg["use_nmap"] and len(chunk) <= 128:
                nmap_map = self._run_nmap_chunk([ip for ip, _ in chunk], ports_list)

            def scan_single_host(ip_pair):
                nonlocal completed_probes
                ip_str, hint_host = ip_pair
                if self.stop_requested:
                    return []

                self._update_live_host_telemetry(ip_str, "PROBING", current_port=ports_list[0] if ports_list else 0)
                host_findings = []
                hostname = hint_host or self._fast_ptr_lookup(ip_str, 0.15)

                h_hash = ip_digest(ip_str)
                ov = overrides.get(h_hash)
                if ov and ov.get("custom_hostname_enc"):
                    dec_h = AtRestCipher.decrypt(ov["custom_hostname_enc"])
                    if dec_h:
                        hostname = dec_h

                host_has_open = False
                for port in ports_list:
                    if self.stop_requested:
                        break
                    limiter.acquire()
                    srv_hint = COMMON_SERVICES.get(port, "tcp")

                    with self.lock:
                        self.progress["current_ip"] = ip_str
                        self.progress["current_port"] = port
                        self.progress["current_service"] = srv_hint
                        if self.progress["current_stage"] not in (3, 4):
                            self.progress["current_stage"] = 2
                            self.progress["stage_label"] = f"Etap 2/4: Skan portu {ip_str}:{port}"

                    self._update_live_host_telemetry(ip_str, "ONLINE" if host_has_open else "PROBING", current_port=port)

                    is_open = False
                    srv_name = nmap_map.get(ip_str, {}).get(port, "")

                    if srv_name:
                        is_open = True
                    else:
                        try:
                            with socket.create_connection((ip_str, port), timeout=mode_cfg["timeout"]):
                                is_open = True
                        except Exception:
                            is_open = False

                    if is_open:
                        host_has_open = True
                        if not srv_name:
                            srv_name = srv_hint

                        self._update_live_host_telemetry(ip_str, "ONLINE", current_port=port, open_port=port, service=srv_name)

                        http_data = None
                        is_http_port = port in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090) or "http" in srv_name.lower()
                        if is_http_port:
                            with self.lock:
                                self.progress["current_stage"] = 3
                                self.progress["stage_label"] = f"Etap 3/4: HTTP/TLS Fingerprint ({ip_str}:{port})"
                            use_tls = port in (443, 8443) or "https" in srv_name.lower()
                            http_data = self._probe_http(ip_str, port, hostname, use_tls, mode_cfg["timeout"], mode_cfg["probe_paths"])
                            if not http_data and port in (8080, 8000, 9000):
                                http_data = self._probe_http(ip_str, port, hostname, True, mode_cfg["timeout"], mode_cfg["probe_paths"])

                        with self.lock:
                            self.progress["current_stage"] = 4
                            self.progress["stage_label"] = f"Etap 4/4: Analiza sygnatur ({ip_str}:{port})"

                        techs, env_tag, matched_sigs, confidence = self._evaluate_signatures_and_tech(
                            ip_str, hostname, port, srv_name, http_data, signatures
                        )

                        if ov and ov.get("custom_env"):
                            env_tag = ov["custom_env"]

                        notes_enc = ov["analyst_notes_enc"] if ov and ov.get("analyst_notes_enc") else ""

                        host_findings.append({
                            "ip": ip_str,
                            "ip_hash": h_hash,
                            "hostname": hostname,
                            "port": port,
                            "protocol": "tcp",
                            "service": srv_name,
                            "http_status": http_data["status"] if http_data else 0,
                            "http_title": http_data["title"] if http_data else "",
                            "headers": "\n".join(f"{k}: {v}" for k, v in http_data["headers"].items()) if http_data else "",
                            "cookies": "\n".join(http_data["cookies"]) if http_data else "",
                            "tls_info": http_data["tls"] if http_data else "",
                            "redirect": http_data["redirect"] if http_data else "",
                            "technologies": ", ".join(techs),
                            "environment_tag": env_tag,
                            "matched_signatures": "; ".join(matched_sigs),
                            "confidence": confidence,
                            "notes_enc": notes_enc
                        })

                    # Natychmiastowa aktualizacja licznika sond (pasek postępu nigdy się nie zacina!)
                    with probe_counter_lock:
                        completed_probes += 1
                        cp_now = completed_probes
                    elapsed_now = max(0.05, time.monotonic() - t_start)
                    pps = cp_now / elapsed_now
                    rem_probes = max(0, total_probes - cp_now)
                    eta_now = round(rem_probes / max(1.0, pps), 1)
                    with self.lock:
                        self.progress["completed_probes"] = cp_now
                        self.progress["elapsed_sec"] = round(elapsed_now, 1)
                        self.progress["eta_sec"] = eta_now
                        self.progress["probes_per_sec"] = round(pps, 1)

                self._update_live_host_telemetry(ip_str, "ONLINE" if host_has_open else "CLOSED")
                return host_findings

            chunk_findings = []
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(scan_single_host, item) for item in chunk]
                for fut in as_completed(futures):
                    scanned_count += 1
                    res_list = fut.result()
                    if res_list:
                        chunk_findings.extend(res_list)
                        for item in res_list:
                            active_ip_hashes.add(item["ip_hash"])
                            self.log(f"[OPEN] {item['ip']}:{item['port']} ({item['service']}) -> {item['environment_tag']}")

                    elapsed_now = max(0.05, time.monotonic() - t_start)
                    with self.lock:
                        self.progress["scanned_ips"] = scanned_count
                        self.progress["active_hosts"] = len(active_ip_hashes)
                        self.progress["findings_count"] = len(all_scan_findings) + len(chunk_findings)
                        self.progress["ips_per_sec"] = round(scanned_count / elapsed_now, 1)

            if chunk_findings:
                all_scan_findings.extend(chunk_findings)
                with db_lock:
                    conn = get_db()
                    cur = conn.cursor()
                    for f in chunk_findings:
                        cur.execute("""
                            INSERT INTO findings (
                                scan_id, ip_enc, ip_hash, hostname_enc, port, protocol, service,
                                http_status, http_title_enc, headers_enc, cookies_enc, tls_info_enc,
                                redirect_enc, technologies, environment_tag, matched_signatures,
                                confidence, analyst_notes_enc
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            scan_id,
                            AtRestCipher.encrypt(f["ip"]),
                            f["ip_hash"],
                            AtRestCipher.encrypt(f["hostname"]),
                            f["port"],
                            f["protocol"],
                            f["service"],
                            f["http_status"],
                            AtRestCipher.encrypt(f["http_title"]),
                            AtRestCipher.encrypt(f["headers"]),
                            AtRestCipher.encrypt(f["cookies"]),
                            AtRestCipher.encrypt(f["tls_info"]),
                            AtRestCipher.encrypt(f["redirect"]),
                            f["technologies"],
                            f["environment_tag"],
                            f["matched_signatures"],
                            f["confidence"],
                            f["notes_enc"]
                        ))
                    conn.commit()
                    conn.close()

        now_iso = datetime.now().isoformat(timespec="seconds")
        duration = round(time.monotonic() - t_start, 2)

        interesting_items = [f for f in all_scan_findings if f["environment_tag"] != "PROD/STANDARD" or f["matched_signatures"]]
        unique_hosts_list = sorted(list({f["ip"] for f in all_scan_findings}))
        summary_data = {
            "scan_id": scan_id,
            "target": target_label,
            "mode": mode_cfg["name"],
            "started_at": started_iso,
            "finished_at": now_iso,
            "duration_sec": duration,
            "status": status_final,
            "total_ips": total_ips,
            "scanned_ips": scanned_count,
            "active_hosts_count": len(active_ip_hashes),
            "active_hosts_list": unique_hosts_list,
            "services_count": len(all_scan_findings),
            "interesting_count": len(interesting_items),
            "highlights": [
                f"{x['ip']}:{x['port']} ({x['service']}) — {x['environment_tag']} | Tech: {x['technologies'] or 'brak'} | Sygnatury: {x['matched_signatures'] or 'brak'}"
                for x in all_scan_findings
            ]
        }

        with db_lock:
            conn = get_db()
            cur = conn.cursor()
            for ip_str, _ in targets_expanded:
                h_hash = ip_digest(ip_str)
                cur.execute("SELECT * FROM host_stability WHERE ip_hash = ?", (h_hash,))
                row = cur.fetchone()
                if h_hash in active_ip_hashes:
                    if row:
                        cur.execute("""
                            UPDATE host_stability SET seen_count = seen_count + 1, missed_streak = 0,
                            last_seen = ?, state = 'ONLINE' WHERE ip_hash = ?
                        """, (now_iso, h_hash))
                    else:
                        cur.execute("""
                            INSERT INTO host_stability (ip_hash, ip_enc, seen_count, missed_streak, last_seen, state)
                            VALUES (?, ?, 1, 0, ?, 'ONLINE')
                        """, (h_hash, AtRestCipher.encrypt(ip_str), now_iso))
                else:
                    if row:
                        new_streak = row["missed_streak"] + 1
                        new_state = "OFFLINE" if new_streak >= offline_threshold else "INTERMITTENT (Niestabilny)"
                        cur.execute("UPDATE host_stability SET missed_streak = ?, state = ? WHERE ip_hash = ?",
                                    (new_streak, new_state, h_hash))

            cur.execute("""
                UPDATE scans SET finished_at = ?, duration_sec = ?, status = ?,
                total_ips = ?, scanned_ips = ?, active_hosts = ?, summary_json = ? WHERE id = ?
            """, (now_iso, duration, status_final, total_ips, scanned_count, len(active_ip_hashes),
                  json.dumps(summary_data, ensure_ascii=False), scan_id))
            conn.commit()
            conn.close()

        with self.lock:
            self.running = False
            self.progress["running"] = False
            self.progress["completed_probes"] = total_probes
            self.progress["elapsed_sec"] = duration
            self.progress["eta_sec"] = 0.0
            self.progress["current_stage"] = 4
            self.progress["stage_label"] = "Zakończono wszystkie 4 etapy skanowania"
            self.progress["last_summary"] = summary_data
            self.progress["status_text"] = f"Zakończono ({status_final}) w {duration}s"

        self.log(f"[DONE] Skan #{scan_id} zakończony. Aktywne hosty: {len(active_ip_hashes)}, Usługi: {len(all_scan_findings)}, Czas: {duration}s.")


SCANNER = ScanManager()


# ==============================================================================
# PORÓWNYWANIE SKANÓW (DIFF), DEFECTDOJO I HARMONOGRAM
# ==============================================================================

def get_decrypted_findings(scan_id: int) -> list:
    with db_lock:
        conn = get_db()
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,)).fetchall()
        conn.close()

    return [{
        "id": r["id"],
        "scan_id": r["scan_id"],
        "ip": AtRestCipher.decrypt(r["ip_enc"]),
        "ip_hash": r["ip_hash"],
        "hostname": AtRestCipher.decrypt(r["hostname_enc"]),
        "port": r["port"],
        "protocol": r["protocol"],
        "service": r["service"],
        "http_status": r["http_status"],
        "http_title": AtRestCipher.decrypt(r["http_title_enc"]),
        "headers": AtRestCipher.decrypt(r["headers_enc"]),
        "cookies": AtRestCipher.decrypt(r["cookies_enc"]),
        "tls_info": AtRestCipher.decrypt(r["tls_info_enc"]),
        "redirect": AtRestCipher.decrypt(r["redirect_enc"]),
        "technologies": r["technologies"],
        "environment_tag": r["environment_tag"],
        "matched_signatures": r["matched_signatures"],
        "confidence": r["confidence"],
        "analyst_notes": AtRestCipher.decrypt(r["analyst_notes_enc"]),
        "custom_status": r["custom_status"]
    } for r in rows]


def compare_scans(scan_a_id: int, scan_b_id: int) -> dict:
    list_a = get_decrypted_findings(scan_a_id)
    list_b = get_decrypted_findings(scan_b_id)
    map_a = {(x["ip"], x["port"], x["protocol"]): x for x in list_a}
    map_b = {(x["ip"], x["port"], x["protocol"]): x for x in list_b}

    added, removed, changed = [], [], []
    for key, item_b in map_b.items():
        if key not in map_a:
            added.append(item_b)
        else:
            item_a = map_a[key]
            diffs = []
            for field in ("service", "http_status", "http_title", "technologies", "tls_info", "environment_tag", "matched_signatures"):
                if str(item_a.get(field, "")) != str(item_b.get(field, "")):
                    diffs.append(f"{field}: '{item_a.get(field)}' -> '{item_b.get(field)}'")
            if diffs:
                copy_b = dict(item_b)
                copy_b["changes"] = "; ".join(diffs)
                changed.append(copy_b)

    for key, item_a in map_a.items():
        if key not in map_b:
            removed.append(item_a)

    return {"scan_a": scan_a_id, "scan_b": scan_b_id, "added": added, "removed": removed, "changed": changed}


def push_to_defectdojo(dd_url: str, api_key: str, engagement_id: int, findings: list):
    if not dd_url or not api_key:
        return False, "Brak URL lub klucza API DefectDojo."
    endpoint = dd_url.rstrip("/") + "/api/v2/findings/"
    sent = 0
    errors = []
    for f in findings:
        title = f"[Proculus Discovery] {f['ip']}:{f['port']} ({f['service']}) - {f['environment_tag']}"
        desc = (
            f"**Host:** {f['ip']} ({f['hostname']})\n"
            f"**Port:** {f['port']}/{f['protocol']} ({f['service']})\n"
            f"**Tytuł HTTP:** {f['http_title']} (HTTP {f['http_status']})\n"
            f"**Technologie:** {f['technologies']}\n"
            f"**Sygnatury:** {f['matched_signatures']}\n"
            f"**TLS:** {f['tls_info']}\n"
            f"**Notatki:** {f['analyst_notes']}"
        )
        payload = json.dumps({
            "title": title[:200],
            "description": desc,
            "severity": "Medium" if ("CRITICAL" in f["matched_signatures"] or "MEDIUM" in f["matched_signatures"]) else "Info",
            "active": True,
            "verified": False,
            "numerical_severity": "S3" if "MEDIUM" in f["matched_signatures"] else "S4",
            "engagement": int(engagement_id),
            "found_by": [1],
            "endpoints": [f"{f['ip']}:{f['port']}"]
        }).encode("utf-8")

        req = urllib.request.Request(endpoint, data=payload, method="POST", headers={
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        })
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status in (200, 201):
                    sent += 1
        except Exception as e:
            errors.append(str(e))
    if sent > 0:
        return True, f"Wysłano {sent} obserwacji do DefectDojo."
    return False, f"Błąd wysyłki do DefectDojo: {errors[:1]}"


def scheduler_loop():
    while True:
        time.sleep(20)
        try:
            with db_lock:
                conn = get_db()
                sched = conn.execute("SELECT * FROM schedules WHERE enabled = 1 LIMIT 1").fetchone()
                conn.close()
            if not sched or SCANNER.running:
                continue
            now = datetime.now()
            last_run = sched["last_run"]
            should_run = True if not last_run else ((now - datetime.fromisoformat(last_run)).total_seconds() / 60.0 >= sched["interval_minutes"])
            if should_run and SCANNER._within_window(sched["window_start"], sched["window_end"]):
                with db_lock:
                    conn = get_db()
                    conn.execute("UPDATE schedules SET last_run = ? WHERE id = ?", (now.isoformat(timespec="seconds"), sched["id"]))
                    conn.commit()
                    conn.close()
                SCANNER.start_scan(
                    mode=sched["mode"], rate_limit=sched["rate_limit"], chunk_size=sched["chunk_size"],
                    win_start=sched["window_start"], win_end=sched["window_end"], offline_threshold=sched["offline_threshold"]
                )
        except Exception:
            pass


# ==============================================================================
# INTERFEJS APLIKACJI PROCULUS (DESIGN Z LOGO + WIZUALIZACJA HOSTÓW I PORTÓW)
# ==============================================================================

SESSIONS = {}

HTML_APP = r"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Proculus — Attack Surface Intelligence</title>
<style>
  :root {
    --bg: #f4f7fb;
    --panel: #ffffff;
    --panel2: #eef4fb;
    --border: #d7e2f0;
    --text: #0f172a;
    --muted: #475569;
    --accent: #0077e6;
    --accent-hover: #005bb5;
    --accent-soft: rgba(0, 119, 230, 0.08);
    --accent2: #0ea5e9;
    --ok: #059669;
    --ok-bg: #ecfdf5;
    --danger: #dc2626;
    --danger-bg: #fef2f2;
    --warn: #d97706;
    --warn-bg: #fffbeb;
    --shadow: 0 4px 18px rgba(0, 119, 230, 0.06);
  }
  * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
  body { margin: 0; background: var(--bg); color: var(--text); overflow-x: hidden; }
  .mono { font-family: 'Consolas', 'Fira Code', monospace; }

  header {
    background: var(--panel); border-bottom: 1px solid var(--border);
    padding: 10px 24px; display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 10px; box-shadow: 0 2px 10px rgba(15, 23, 42, 0.03);
    position: sticky; top: 0; z-index: 40;
  }
  .brand-wrap { display: flex; align-items: center; gap: 12px; }
  .brand-title { font-weight: 800; font-size: 20px; letter-spacing: 2px; color: var(--accent); line-height: 1; }
  .brand-sub { font-size: 11px; color: var(--muted); font-weight: 600; letter-spacing: 0.4px; margin-top: 2px; }

  .badge { padding: 3px 9px; border-radius: 6px; font-size: 11px; font-weight: 700; display: inline-block; }
  .b-green { background: var(--ok-bg); color: var(--ok); border: 1px solid rgba(5, 150, 105, 0.3); }
  .b-red { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(220, 38, 38, 0.3); }
  .b-warn { background: var(--warn-bg); color: var(--warn); border: 1px solid rgba(217, 119, 6, 0.3); }
  .b-blue { background: #eff6ff; color: var(--accent); border: 1px solid rgba(0, 119, 230, 0.3); }

  .container { max-width: 1500px; margin: 0 auto; padding: 18px 22px; }
  .tabs {
    display: flex; gap: 4px; background: var(--panel); padding: 6px; border-radius: 10px;
    border: 1px solid var(--border); margin-bottom: 18px; flex-wrap: wrap; box-shadow: var(--shadow);
  }
  .tab-btn {
    background: transparent; color: var(--muted); border: none; border-radius: 7px;
    padding: 9px 14px; cursor: pointer; font-weight: 600; font-size: 13px; transition: 0.18s;
  }
  .tab-btn:hover { color: var(--accent); background: var(--panel2); }
  .tab-btn.active { color: #ffffff; background: var(--accent); box-shadow: 0 2px 8px rgba(0, 119, 230, 0.3); }
  .view { display: none; }
  .view.active { display: block; }

  .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 18px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  @media (max-width: 980px) { .grid-2 { grid-template-columns: 1fr; } }

  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 18px; margin-bottom: 16px; position: relative; box-shadow: var(--shadow);
    transition: box-shadow 0.25s, border-color 0.25s;
  }
  .card h3 {
    margin: 0 0 12px 0; font-size: 13px; text-transform: uppercase;
    color: var(--accent); letter-spacing: 0.7px; font-weight: 800;
  }
  .kpi-val { font-size: 28px; font-weight: 800; margin-top: 4px; color: var(--text); }

  label {
    display: flex; align-items: center; justify-content: space-between;
    font-size: 12.5px; color: #1e293b; margin-bottom: 5px; margin-top: 11px; font-weight: 600;
  }
  .hint-icon {
    color: var(--accent); font-size: 11px; cursor: help; background: #eff6ff;
    border: 1px solid rgba(0, 119, 230, 0.35); border-radius: 50%;
    width: 17px; height: 17px; display: inline-flex; align-items: center; justify-content: center;
  }
  input, select, textarea {
    width: 100%; background: #f8fafc; border: 1px solid #cbd5e1; color: var(--text);
    padding: 8px 11px; border-radius: 7px; font-size: 13px; transition: border-color 0.2s, box-shadow 0.2s;
  }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: var(--accent); background: #ffffff;
    box-shadow: 0 0 0 3px rgba(0, 119, 230, 0.12);
  }
  button {
    background: var(--accent); color: #ffffff; border: none; padding: 9px 15px;
    border-radius: 7px; font-weight: 700; cursor: pointer; font-size: 13px; transition: 0.18s;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: 0.45; cursor: not-allowed; }
  button.sec { background: var(--panel2); color: var(--accent); border: 1px solid rgba(0, 119, 230, 0.25); }
  button.sec:hover { background: #dbeafe; }
  button.danger { background: var(--danger); color: #ffffff; }
  button.danger:hover { background: #b91c1c; }

  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-size: 11px; text-transform: uppercase; background: #f8fafc; font-weight: 700; }
  tr:hover { background: #f8fbff; }

  /* PRZEWIDYWANY CZAS SKANOWANIA (ETA MATRIX) */
  .eta-box {
    background: #f8fbff; border: 1px solid #cfe2fa; border-radius: 8px;
    padding: 10px 12px; margin-top: 10px;
  }
  .eta-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; margin-top: 6px; }
  .eta-item {
    display: flex; justify-content: space-between; align-items: center;
    background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px;
    padding: 5px 9px; font-size: 11.5px;
  }
  .eta-item.active-mode { border-color: var(--accent); background: #eff6ff; font-weight: 700; }

  /* DYMKI WYJAŚNIEŃ PO NAJECHANIU */
  #hoverTooltip {
    position: fixed; display: none; z-index: 9999; max-width: 340px;
    background: #0f172a; border: 1px solid var(--accent2); color: #f8fafc;
    padding: 10px 13px; border-radius: 8px; font-size: 12.5px; line-height: 1.45;
    box-shadow: 0 10px 28px rgba(15, 23, 42, 0.35); pointer-events: none;
  }
  #hoverTooltip b { color: #38bdf8; display: block; margin-bottom: 3px; }

  /* WIZUALIZACJA ETAPÓW SKANOWANIA ORAZ HOSTÓW I PORTÓW NA ŻYWO */
  .stages-bar {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 10px;
  }
  .stage-pill {
    background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 7px;
    padding: 7px 8px; font-size: 11px; color: var(--muted); transition: 0.25s;
  }
  .stage-pill b { display: block; font-size: 11.5px; color: #334155; margin-bottom: 1px; }
  .stage-pill.active {
    background: #eff6ff; border-color: var(--accent); color: var(--accent);
    box-shadow: 0 0 0 2px rgba(0, 119, 230, 0.15);
  }
  .stage-pill.active b { color: var(--accent); }
  .stage-pill.done {
    background: var(--ok-bg); border-color: rgba(5, 150, 105, 0.4); color: var(--ok);
  }
  .stage-pill.done b { color: var(--ok); }

  .viz-stage {
    position: relative; background: linear-gradient(180deg, #f8fbff 0%, #eef5fc 100%);
    border: 1px solid #cbd9ec; border-radius: 10px; overflow: hidden; margin-bottom: 12px;
  }
  #scanVizCanvas { display: block; width: 100%; height: 225px; }
  .viz-footer-bar {
    background: #ffffff; border-top: 1px solid #dbe4f0; padding: 6px 12px;
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;
    font-size: 11.5px; color: var(--muted);
  }
  .pulse-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: #94a3b8; margin-right: 6px;
  }
  .pulse-dot.live {
    background: var(--accent); box-shadow: 0 0 0 4px rgba(0, 119, 230, 0.2);
    animation: pulseBlue 1.2s infinite;
  }
  @keyframes pulseBlue { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.25); } }

  .prog-wrap {
    background: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 8px;
    height: 22px; overflow: hidden; margin: 8px 0; position: relative;
  }
  .prog-bar {
    background: linear-gradient(90deg, #005bb5, #0077e6, #38bdf8);
    height: 100%; width: 0%; will-change: width;
  }
  .log-box {
    background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 7px; padding: 9px 11px;
    height: 125px; overflow-y: auto; font-size: 11.5px; color: #1e293b; line-height: 1.45;
  }

  /* INTERAKTYWNY PRZEWODNIK PROCULUS */
  .tour-highlight {
    position: relative !important;
    z-index: 1002 !important;
    box-shadow: 0 0 0 4px var(--accent), 0 0 30px rgba(0, 119, 230, 0.45) !important;
    border-color: var(--accent) !important;
  }
  #tourBackdrop {
    display: none; position: fixed; inset: 0; background: rgba(15, 23, 42, 0.55); z-index: 1000;
  }
  #mascotBox {
    display: none; position: fixed; z-index: 1005; width: 400px; max-width: 92vw;
    background: #ffffff; border: 2px solid var(--accent); border-radius: 14px; padding: 18px;
    box-shadow: 0 20px 50px rgba(15, 23, 42, 0.28); transition: all 0.3s ease;
  }
  .mascot-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
  .mascot-avatar {
    background: #eff6ff; border: 1px solid rgba(0, 119, 230, 0.35);
    border-radius: 50%; width: 58px; height: 58px; display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .mascot-pointer {
    position: absolute; font-size: 26px; filter: drop-shadow(0 2px 6px rgba(0,119,230,0.4));
    animation: pointPulse 1s infinite alternate;
  }
  @keyframes pointPulse { from { transform: translateX(0); } to { transform: translateX(-7px); } }

  /* SEKCJA PODSUMOWANIA SKANU NA DOLE */
  .summary-card {
    border: 1px solid rgba(0, 119, 230, 0.35);
    background: linear-gradient(135deg, #ffffff 0%, #f0f7ff 100%);
  }
  .summary-report-box {
    background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 7px;
    padding: 12px; font-size: 12.5px; line-height: 1.55; color: #0f172a;
    max-height: 230px; overflow-y: auto; white-space: pre-wrap;
  }

  #loginScreen {
    max-width: 420px; margin: 70px auto; background: var(--panel); padding: 30px;
    border-radius: 14px; border: 1px solid var(--border); box-shadow: 0 12px 36px rgba(0, 119, 230, 0.08);
  }
  .modal-bg {
    display: none; position: fixed; inset: 0; background: rgba(15, 23, 42, 0.55);
    align-items: center; justify-content: center; z-index: 50;
  }
  .modal { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 22px; width: 540px; max-width: 95vw; box-shadow: 0 20px 45px rgba(15,23,42,0.2); }
</style>
</head>
<body>

<!-- DEFINICJA WEKTOROWEGO LOGO PROCULUS (IDENTYCZNE Z PLIKIEM PROCULUS.PNG) -->
<svg width="0" height="0" style="position:absolute">
  <defs>
    <g id="proculus-emblem">
      <!-- Zewnętrzny łuk C -->
      <path d="M 74 20 A 40 40 0 1 0 74 80" fill="none" stroke="#0077e6" stroke-width="6.5" stroke-linecap="butt"/>
      <!-- Korona promienista (6 promieni) -->
      <polygon points="31,48 21,42 35,44" fill="#0077e6"/>
      <polygon points="35,44 26,34 39,40" fill="#0077e6"/>
      <polygon points="39,40 34,27 44,36" fill="#0077e6"/>
      <polygon points="44,36 43,22 49,33" fill="#0077e6"/>
      <polygon points="49,33 52,20 54,31" fill="#0077e6"/>
      <!-- Opaska korony -->
      <polygon points="30,49 55,30 58,34 33,53" fill="#0077e6"/>
      <!-- Profil głowy Proculusa -->
      <path d="M 54 35 L 59 38 L 60 44 L 58 49 L 64 55 L 60 57 L 60 61 L 58 63 L 59 66 L 54 68 L 51 67 L 51 77 L 32 69 L 36 62 L 34 56 L 36 51"
            fill="none" stroke="#0077e6" stroke-width="2.6" stroke-linejoin="round" stroke-linecap="round"/>
      <!-- Oko -->
      <polygon points="53,47 58,49 53,51" fill="#0077e6"/>
      <!-- Strumień binarny z oka -->
      <text x="65" y="45" font-family="Consolas, monospace" font-size="4.4" font-weight="bold" fill="#0077e6">0101<tspan fill="#60a5fa">0100</tspan><tspan fill="#bfdbfe">10</tspan></text>
      <text x="65" y="50" font-family="Consolas, monospace" font-size="4.4" font-weight="bold" fill="#0077e6">1010<tspan fill="#60a5fa">0101</tspan><tspan fill="#bfdbfe">01</tspan></text>
      <text x="65" y="55" font-family="Consolas, monospace" font-size="4.4" font-weight="bold" fill="#0077e6">0100<tspan fill="#60a5fa">1010</tspan><tspan fill="#bfdbfe">00</tspan></text>
    </g>
  </defs>
</svg>

<!-- DYMKEK PODPOWIEDZI PO NAJECHANIU -->
<div id="hoverTooltip"></div>

<!-- TŁO I PRZEWODNIK PROCULUS -->
<div id="tourBackdrop"></div>
<div id="mascotBox">
  <div id="mascotArrow" class="mascot-pointer" style="left:-34px; top:24px;">👈</div>
  <div class="mascot-header">
    <div class="mascot-avatar">
      <svg viewBox="0 0 100 100" width="46" height="46"><use href="#proculus-emblem"/></svg>
    </div>
    <div>
      <div style="font-weight:800; color:var(--accent); font-size:14.5px; letter-spacing:0.5px;">PROCULUS — Przewodnik Systemowy</div>
      <div id="tourStepCounter" style="font-size:11.5px; color:var(--muted);">Krok 1 z 6</div>
    </div>
  </div>
  <div id="tourText" style="font-size:13px; line-height:1.5; color:var(--text); margin-bottom:14px;"></div>
  <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
    <button class="sec" onclick="endTour()">Pomiń przewodnik</button>
    <div style="display:flex; gap:6px;">
      <button class="sec" id="tourPrevBtn" onclick="prevTourStep()">◀ Wstecz</button>
      <button id="tourNextBtn" onclick="nextTourStep()">Dalej ▶</button>
    </div>
  </div>
</div>

<!-- EKRAN LOGOWANIA -->
<div id="loginScreen">
  <div style="text-align:center; margin-bottom:16px;">
    <svg viewBox="0 0 100 100" width="84" height="84"><use href="#proculus-emblem"/></svg>
    <div class="brand-title" style="font-size:24px; margin-top:4px;">PROCULUS</div>
    <div style="font-size:12px; color:var(--muted); margin-top:4px;">Attack Surface Intelligence // CBI AGH</div>
    <div style="margin-top:6px;"><span class="badge b-green">Baza Danych Zaszyfrowana At-Rest</span></div>
  </div>
  <label>Użytkownik</label>
  <input id="loginUser" value="admin">
  <label>Hasło</label>
  <input id="loginPass" type="password" value="admin123">
  <button style="width:100%; margin-top:16px;" onclick="doLogin()">Uruchom Konsolę Proculus</button>
  <div id="loginErr" style="color:var(--danger); font-size:12px; margin-top:10px;"></div>
  <div style="margin-top:16px; padding-top:12px; border-top:1px solid var(--border); font-size:11.5px; color:var(--muted);">
    <b>Konta demonstracyjne RBAC:</b><br>
    • <code>admin / admin123</code> (Administracja)<br>
    • <code>operator / oper123</code> (Dodawanie, usuwanie, modyfikacja)<br>
    • <code>analyst / anal123</code> (Modyfikacja i odczyt)<br>
    • <code>viewer / view123</code> (Odczyt)
  </div>
</div>

<!-- GŁÓWNY INTERFEJS APLIKACJI PROCULUS -->
<div id="appScreen" style="display:none;">
  <header>
    <div class="brand-wrap">
      <svg viewBox="0 0 100 100" width="42" height="42"><use href="#proculus-emblem"/></svg>
      <div>
        <div class="brand-title">PROCULUS</div>
        <div class="brand-sub">ATTACK SURFACE INTELLIGENCE // CBI AGH</div>
      </div>
      <span class="badge b-green">DB ENCRYPTED</span>
      <span class="badge b-blue" id="detectedNetBadge">Wykrywanie sieci...</span>
    </div>
    <div style="display:flex; align-items:center; gap:10px; font-size:13px;">
      <button class="sec" onclick="startTour(true)" data-tip-title="Przewodnik Proculus" data-tip="Uruchamia interaktywny samouczek Proculusa, który omawia krok po kroku konfigurację skanu, szacowany czas i wizualizację portów.">Przewodnik</button>
      <span>Rola: <b id="uiUser"></b> (<span id="uiRole" class="badge b-blue"></span>)</span>
      <button class="sec" onclick="doLogout()">Wyloguj</button>
    </div>
  </header>

  <div class="container">
    <div class="tabs" id="mainTabs">
      <button class="tab-btn active" onclick="openTab('dashboard', this)">1. Dashboard & Skaner</button>
      <button class="tab-btn" onclick="openTab('findings', this)">2. Wyniki & Edycja</button>
      <button class="tab-btn" onclick="openTab('diff', this)">3. Zmiany w Czasie (Diff)</button>
      <button class="tab-btn" onclick="openTab('targets', this)">4. Cele (CSV / JSON)</button>
      <button class="tab-btn" onclick="openTab('signatures', this)">5. Własne Sygnatury</button>
      <button class="tab-btn" onclick="openTab('schedule', this)">6. Harmonogram & DefectDojo</button>
      <button class="tab-btn" id="tabBtnAdmin" onclick="openTab('admin', this)">7. Administracja RBAC</button>
    </div>

    <!-- TAB 1: DASHBOARD -->
    <div id="view-dashboard" class="view active">
      <div class="grid-4" id="tour-kpi">
        <div class="card" data-tip-title="Aktywne Hosty" data-tip="Liczba unikalnych urządzeń (IP) w sieci, które odpowiedziały na co najmniej jeden port lub usługę.">
          <h3>Aktywne Hosty</h3><div class="kpi-val" id="kpiHosts">0</div>
        </div>
        <div class="card" data-tip-title="Wykryte Usługi" data-tip="Suma wszystkich otwartych portów oraz zidentyfikowanych aplikacji webowych, serwerów i baz danych.">
          <h3>Wykryte Usługi</h3><div class="kpi-val" style="color:var(--accent);" id="kpiServices">0</div>
        </div>
        <div class="card" data-tip-title="Panele Admina i Staging" data-tip="Usługi oznaczone jako potencjalnie wrażliwe: panele logowania, środowiska testowe/staging lub dopasowane sygnatury.">
          <h3>Panele Admina / Staging</h3><div class="kpi-val" style="color:var(--warn);" id="kpiInteresting">0</div>
        </div>
        <div class="card" data-tip-title="Hosty Niestabilne" data-tip="Urządzenia pojawiające się tylko o określonych porach dnia (nie odpowiadające w części skanów).">
          <h3>Hosty Niestabilne</h3><div class="kpi-val" style="color:var(--danger);" id="kpiUnstable">0</div>
        </div>
      </div>

      <div class="grid-2">
        <!-- KONFIGURACJA SKANU + PRZEWIDYWANY CZAS KAŻDEGO RODZAJU -->
        <div class="card" id="tour-config">
          <h3>Konfiguracja Skanowania & Szacowanie Czasu</h3>

          <div id="field-target-wrap" data-tip-title="Wybór sieci / celu skanowania" data-tip="Proculus automatycznie wykrył adres IP Twojego komputera i przygotował gotowe zakresy sieciowe do wyboru. Możesz też wpisać własny zakres CIDR lub domenę.">
            <label>Wybierz sieć lub cel do przeskanowania <span class="hint-icon">?</span></label>
            <select id="targetPresetSelect" onchange="onTargetPresetChange()"></select>
            <div id="presetDescBox" style="font-size:11.5px; color:var(--accent); margin-top:5px;"></div>
            <div id="customTargetBox" style="display:none; margin-top:8px;">
              <input id="customTargetInput" oninput="updateTimeEstimates()" placeholder="Wpisz ręcznie np. 192.168.88.0/24, 10.0.0.0/16 lub domena.pl">
            </div>
          </div>

          <div class="grid-2">
            <div id="field-mode-wrap" data-tip-title="Tryb skanowania" data-tip="Określa głębokość analizy i liczbę sprawdzanych portów. Obok każdego trybu widzisz przewidywany czas trwania skanu dla wybranej sieci.">
              <label>Tryb skanowania <span class="hint-icon">?</span></label>
              <select id="scanMode" onchange="updateTimeEstimates()"></select>
            </div>

            <div id="field-rate-wrap" data-tip-title="Prędkość / Limit zapytań" data-tip="Kontroluje intensywność ruchu sieciowego (zapytań na sekundę). Zmiana prędkości natychmiast przelicza przewidywany czas skanowania.">
              <label>Prędkość skanu (Rate Limit) <span class="hint-icon">?</span></label>
              <select id="scanRate" onchange="toggleCustomNumeric('scanRate', 'customRateInput'); updateTimeEstimates();">
                <option value="30">Ostrożna — 30 zapytań/s</option>
                <option value="150" selected>Zalecana LAN — 150 zapytań/s</option>
                <option value="400">Wysoka — 400 zapytań/s</option>
                <option value="800">Maksymalna (>10 000 IP) — 800 zapytań/s</option>
                <option value="__CUSTOM__">✎ Wpisz własną wartość...</option>
              </select>
              <input id="customRateInput" type="number" value="150" oninput="updateTimeEstimates()" style="display:none; margin-top:6px;" placeholder="np. 200">
            </div>
          </div>

          <!-- TABELA PRZEWIDYWANEGO CZASU KAŻDEGO RODZAJU SKANOWANIA -->
          <div class="eta-box" id="field-eta-wrap" data-tip-title="Przewidywany czas skanowania" data-tip="Automatyczna kalkulacja czasu trwania dla wszystkich 4 trybów skanowania na podstawie liczby hostów w wybranym celu, liczby portów oraz limitu zapytań na sekundę.">
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:11.5px; font-weight:700; color:var(--accent);">
              <span>⏱ Przewidywany czas każdego rodzaju skanowania</span>
              <span id="estHostCountLabel" class="mono">Cel: 254 hosty</span>
            </div>
            <div class="eta-grid" id="etaModesGrid"></div>
          </div>

          <div class="grid-2">
            <div id="field-chunk-wrap" data-tip-title="Podział sieci na podgrupy (Chunk Size)" data-tip="Dzieli rozległą sieć na mniejsze paczki adresów. Wyniki zapisują się na bieżąco po każdej paczce, a skan można bezpiecznie wstrzymać po przekroczeniu okna czasowego.">
              <label>Podział na podgrupy (Paczki IP) <span class="hint-icon">?</span></label>
              <select id="scanChunk" onchange="toggleCustomNumeric('scanChunk', 'customChunkInput')">
                <option value="32">Małe paczki — 32 IP</option>
                <option value="64" selected>Zalecane LAN — 64 IP</option>
                <option value="256">Standardowe — 256 IP</option>
                <option value="512">Duże sieci (>10k IP) — 512 IP</option>
                <option value="__CUSTOM__">✎ Wpisz własny rozmiar paczki...</option>
              </select>
              <input id="customChunkInput" type="number" value="64" style="display:none; margin-top:6px;">
            </div>

            <div id="field-offline-wrap" data-tip-title="Próg uznania hosta za OFFLINE" data-tip="Host znikający na 1–2 skany otrzymuje status NIESTABILNY, a dopiero po przekroczeniu tego progu jest raportowany jako OFFLINE.">
              <label>Próg uznania za OFFLINE <span class="hint-icon">?</span></label>
              <select id="scanOfflineThresh">
                <option value="1">1 brak odpowiedzi (natychmiast OFFLINE)</option>
                <option value="3" selected>3 braki odpowiedzi z rzędu (Zalecane)</option>
                <option value="5">5 braków odpowiedzi z rzędu</option>
              </select>
            </div>
          </div>

          <div id="field-window-wrap" data-tip-title="Dozwolone okno czasowe skanowania" data-tip="Jeśli skan przekroczy godzinę końcową okna czasowego, zatrzyma się automatycznie i wznowi w kolejnym oknie.">
            <label>Dozwolone okno czasowe pracy skanera <span class="hint-icon">?</span></label>
            <select id="winPreset" onchange="onWinPresetChange()">
              <option value="00:00|23:59" selected>Całodobowo (00:00 — 23:59, brak ograniczeń)</option>
              <option value="08:00|16:00">Godziny pracy (08:00 — 16:00)</option>
              <option value="22:00|06:00">Okno nocne / serwisowe (22:00 — 06:00)</option>
              <option value="__CUSTOM__">✎ Wpisz własne godziny (HH:MM)...</option>
            </select>
            <div id="customWinBox" class="grid-2" style="display:none; margin-top:6px;">
              <input id="winStart" value="00:00" placeholder="Start HH:MM">
              <input id="winEnd" value="23:59" placeholder="Koniec HH:MM">
            </div>
          </div>

          <div style="margin-top:15px; display:flex; gap:10px; flex-wrap:wrap;" id="tour-start-btn">
            <button id="btnStartScan" onclick="startScan()" data-tip-title="Start Skanowania" data-tip="Uruchamia wielowątkowy silnik Proculus i wizualizację przechodzenia przez hosty i porty na żywo.">▶ Uruchom Skanowanie</button>
            <button id="btnStopScan" class="danger" onclick="stopScan()" data-tip-title="Zatrzymaj Skan" data-tip="Bezpiecznie przerywa bieżące skanowanie, zachowując dotychczas zebrane wyniki.">■ Zatrzymaj</button>
          </div>
        </div>

        <!-- WIZUALIZACJA ETAPÓW SKANOWANIA, HOSTÓW I PORTÓW NA ŻYWO -->
        <div class="card" id="tour-progress">
          <h3>Wizualizacja Etapów Skanowania, Hostów i Portów Na Żywo</h3>

          <!-- PASEK 4 ETAPÓW SKANOWANIA -->
          <div class="stages-bar">
            <div class="stage-pill" id="stagePill1"><b>1. Discovery</b>Podział na podgrupy</div>
            <div class="stage-pill" id="stagePill2"><b>2. Porty TCP</b>Sondowanie usług</div>
            <div class="stage-pill" id="stagePill3"><b>3. HTTP / TLS</b>Nagłówki, CMS, TLS</div>
            <div class="stage-pill" id="stagePill4"><b>4. Sygnatury</b>Dopasowanie & Szyfr</div>
          </div>

          <!-- INTERAKTYWNA MAPA PRZECHODZENIA PRZEZ HOSTY I PORTY -->
          <div class="viz-stage" data-tip-title="Wizualizacja przechodzenia przez hosty i porty" data-tip="Pokazuje na żywo faktycznie skanowane adresy IP oraz sprawdzane na nich numery portów (niebieski = aktualnie badany port, zielony = port otwarty).">
            <canvas id="scanVizCanvas"></canvas>
            <div class="viz-footer-bar mono">
              <span><span class="pulse-dot" id="vizDot"></span><b id="vizLiveTarget">CEL: Oczekiwanie na start</b></span>
              <span id="vizStageLabel" style="color:var(--accent); font-weight:700;">ETAP: IDLE</span>
            </div>
          </div>

          <div style="display:flex; justify-content:space-between; font-size:13px;">
            <span id="progStatus" style="font-weight:700; color:var(--accent);">Gotowy do skanowania</span>
            <span class="mono" id="progNumbers">0% (0 / 0 sond)</span>
          </div>
          <div class="prog-wrap"><div class="prog-bar" id="progBar"></div></div>
          <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--muted); margin-bottom:8px; flex-wrap:wrap; gap:6px;">
            <span>Hosty: <b id="progHostsDone">0/0</b></span>
            <span>Podgrupa: <b id="progChunk">0/0</b></span>
            <span>Czas: <b id="progTime">0.0s</b> (ETA: <b id="progEta">-</b>)</span>
            <span>Prędkość: <b id="progSpeed">0.0 sond/s</b></span>
          </div>
          <div class="log-box mono" id="progLogs"></div>
        </div>
      </div>

      <!-- POLE NA DOLE: PODSUMOWANIE WYKONANEGO SKANU + ZAPIS DO TXT + NOWY SKAN -->
      <div class="card summary-card" id="tour-summary" data-tip-title="Podsumowanie Skanowania" data-tip="Automatyczny raport końcowy ze skanu. Możesz zapisać go jako plik tekstowy (.TXT) i wyczyścić panel pod kolejny skan.">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:10px;">
          <h3 style="margin:0;">📋 Podsumowanie Wykonanego Skanu</h3>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button id="btnSaveTxt" onclick="downloadSummaryTxt()" disabled data-tip-title="Zapisz raport TXT" data-tip="Pobiera kompletne podsumowanie ostatniego skanu w formacie czystego pliku tekstowego (.txt).">💾 Zapisz raport jako plik (.TXT)</button>
            <button class="sec" onclick="resetForNewScan()" data-tip-title="Nowy skan" data-tip="Czyści bieżące podsumowanie i pasek postępu, przygotowując formularz do kolejnego skanu (wyniki historyczne zostają w bazie).">🔄 Wyczyść i zacznij nowy skan</button>
          </div>
        </div>
        <div id="summaryContent" class="summary-report-box mono">Brak zakończonego skanu w bieżącej sesji. Wybierz sieć powyżej i kliknij „Uruchom Skanowanie”, aby wygenerować podsumowanie.</div>
      </div>

      <!-- TABELA STABILNOŚCI HOSTÓW -->
      <div class="card">
        <h3>Monitor Stabilności Hostów (Wykrywanie okresowej dostępności w czasie)</h3>
        <table>
          <thead><tr><th>Adres IP</th><th>Stan dostępności</th><th>Liczba wykryć</th><th>Braki z rzędu</th><th>Ostatnio widziany</th></tr></thead>
          <tbody id="stabilityBody"></tbody>
        </table>
      </div>
    </div>

    <!-- TAB 2: WYNIKI I EDYCJA -->
    <div id="view-findings" class="view">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
          <div style="display:flex; gap:10px; align-items:center;">
            <h3 style="margin:0;">Wykryte Usługi i Artefakty</h3>
            <select id="selectScanView" style="width:270px;" onchange="loadFindings()"></select>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <input id="filterInput" placeholder="Filtruj IP, technologię, nagłówek, ciasteczko..." style="width:260px;" onkeyup="renderFindingsTable()">
            <button class="sec" onclick="exportData('json')">Eksport JSON</button>
            <button class="sec" onclick="exportData('csv')">Eksport CSV</button>
            <button class="sec" onclick="document.getElementById('importFindingsFile').click()">Import JSON/CSV</button>
            <input type="file" id="importFindingsFile" style="display:none" onchange="importFindings(this)">
          </div>
        </div>
        <div style="overflow-x:auto;">
          <table>
            <thead>
              <tr>
                <th>IP / Hostname</th>
                <th>Port / Usługa</th>
                <th>HTTP / Tytuł / Przekierowania</th>
                <th>Technologie & Klasyfikacja</th>
                <th>Nagłówki / Ciasteczka / TLS</th>
                <th>Pewność</th>
                <th>Notatki Analityka</th>
                <th>Akcje</th>
              </tr>
            </thead>
            <tbody id="findingsBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: DIFF -->
    <div id="view-diff" class="view">
      <div class="card">
        <h3>Porównanie Dwóch Przebiegów Skanowania</h3>
        <div style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
          <div><label>Skan bazowy (Starszy)</label><select id="diffScanA" style="width:270px;"></select></div>
          <div><label>Skan docelowy (Nowszy)</label><select id="diffScanB" style="width:270px;"></select></div>
          <button onclick="runDiff()">Porównaj skany</button>
        </div>
      </div>
      <div class="grid-2">
        <div class="card"><h3 style="color:var(--ok);">Nowe usługi (+)</h3><table><thead><tr><th>IP:Port</th><th>Usługa</th><th>Technologie</th></tr></thead><tbody id="diffAdded"></tbody></table></div>
        <div class="card"><h3 style="color:var(--danger);">Znikające usługi (-)</h3><table><thead><tr><th>IP:Port</th><th>Usługa</th><th>Technologie</th></tr></thead><tbody id="diffRemoved"></tbody></table></div>
      </div>
      <div class="card"><h3 style="color:var(--warn);">Zmienione usługi i konfiguracje (~)</h3><table><thead><tr><th>IP:Port</th><th>Wykryte zmiany</th></tr></thead><tbody id="diffChanged"></tbody></table></div>
    </div>

    <!-- TAB 4: CELE -->
    <div id="view-targets" class="view">
      <div class="grid-2">
        <div class="card">
          <h3>Dodaj Cel Ręcznie do Stałej Bazy</h3>
          <label>Adres IP, CIDR lub domena</label>
          <input id="newTargetVal" placeholder="np. 192.168.88.0/24">
          <label>Opis / Jednostka</label>
          <input id="newTargetLabel" placeholder="Sieć lokalna">
          <label>Tagi</label>
          <input id="newTargetTags" placeholder="lan, prod">
          <button style="margin-top:14px;" onclick="addTarget()">Dodaj cel</button>
        </div>
        <div class="card">
          <h3>Import Masowy z Pliku (CSV lub JSON)</h3>
          <p style="font-size:12px; color:var(--muted);">Format CSV: <code>target,label,tags</code> lub tablica JSON.</p>
          <input type="file" id="targetFileInput" accept=".csv,.json">
          <button style="margin-top:14px;" onclick="importTargetsFile()">Importuj cele</button>
        </div>
      </div>
      <div class="card">
        <h3>Zapisane Cele w Bazie (Zaszyfrowane At-Rest)</h3>
        <table><thead><tr><th>ID</th><th>Cel</th><th>Opis</th><th>Tagi</th><th>Akcja</th></tr></thead><tbody id="targetsBody"></tbody></table>
      </div>
    </div>

    <!-- TAB 5: SYGNATURY -->
    <div id="view-signatures" class="view">
      <div class="grid-2">
        <div class="card">
          <h3>Dodaj Bezpieczną Sygnaturę Detekcyjną</h3>
          <label>Nazwa sygnatury</label>
          <input id="sigName" placeholder="np. Router MikroTik WebFig">
          <div class="grid-2">
            <div><label>Kategoria</label><select id="sigCat"><option>CMS</option><option>Framework</option><option>Serwer aplikacyjny</option><option>Panel Admina</option><option>Środowisko</option><option>IoT</option><option>Konfiguracja</option></select></div>
            <div><label>Typ dopasowania</label><select id="sigType"><option value="header">Nagłówek HTTP</option><option value="cookie">Ciasteczko (Cookie)</option><option value="html">Fragment HTML</option><option value="title_or_host">Tytuł strony / Hostname</option><option value="path_probe">Ścieżka (/admin, /login)</option><option value="favicon_hash">Hash Favicony (SHA-256)</option><option value="service">Baner usługi</option></select></div>
          </div>
          <label>Wzorzec (Regex)</label>
          <input id="sigPattern" placeholder="np. MikroTik|RouterOS">
          <label>Poziom istotności</label>
          <select id="sigSev"><option>INFO</option><option>LOW</option><option>MEDIUM</option><option>CRITICAL</option></select>
          <button style="margin-top:14px;" onclick="addSignature()">Zapisz sygnaturę</button>
        </div>
        <div class="card">
          <h3>Aktywne Sygnatury</h3>
          <table><thead><tr><th>Nazwa</th><th>Kategoria</th><th>Typ</th><th>Wzorzec</th><th>Poziom</th><th>Akcja</th></tr></thead><tbody id="sigsBody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- TAB 6: HARMONOGRAM & DEFECTDOJO -->
    <div id="view-schedule" class="view">
      <div class="grid-2">
        <div class="card">
          <h3>Harmonogram Cyklicznych Skanów</h3>
          <label>Częstotliwość uruchamiania (w minutach)</label>
          <input id="schedInterval" type="number" value="120">
          <div class="grid-2">
            <div><label>Okno Start (HH:MM)</label><input id="schedStart" value="00:00"></div>
            <div><label>Okno Koniec (HH:MM)</label><input id="schedEnd" value="23:59"></div>
          </div>
          <div class="grid-2">
            <div><label>Tryb</label><select id="schedMode"><option value="fast">fast</option><option value="balanced">balanced</option><option value="deep">deep</option><option value="stealth">stealth</option></select></div>
            <div><label>Limit zapytań (req/s)</label><input id="schedRate" type="number" value="150"></div>
          </div>
          <label>Status harmonogramu</label>
          <select id="schedEnabled"><option value="0">Wyłączony</option><option value="1">Włączony (Automatyczny)</option></select>
          <button style="margin-top:14px;" onclick="saveSchedule()">Zapisz harmonogram</button>
        </div>
        <div class="card">
          <h3>Integracja z DefectDojo (API v2)</h3>
          <label>URL instancji DefectDojo</label>
          <input id="ddUrl" placeholder="https://demo.defectdojo.org">
          <label>Klucz API (Token)</label>
          <input id="ddToken" type="password" placeholder="Token API v2">
          <label>ID Engagement</label>
          <input id="ddEngagement" type="number" value="1">
          <button style="margin-top:14px;" onclick="sendDefectDojo()">Wyślij aktualny skan do DefectDojo</button>
          <div id="ddMsg" style="font-size:12px; margin-top:10px;"></div>
        </div>
      </div>
    </div>

    <!-- TAB 7: RBAC ADMIN -->
    <div id="view-admin" class="view">
      <div class="grid-2">
        <div class="card">
          <h3>Dodaj Użytkownika RBAC</h3>
          <label>Nazwa użytkownika</label><input id="newUsername">
          <label>Hasło</label><input id="newUserPass" type="password">
          <label>Rola</label>
          <select id="newUserRole"><option>Administracja</option><option>Dodawanie, usuwanie, modyfikacja</option><option>Modyfikacja i odczyt</option><option>Odczyt</option></select>
          <button style="margin-top:14px;" onclick="createUser()">Utwórz konto</button>
        </div>
        <div class="card">
          <h3>Lista Użytkowników</h3>
          <table><thead><tr><th>ID</th><th>Użytkownik</th><th>Rola</th><th>Akcja</th></tr></thead><tbody id="usersBody"></tbody></table>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- MODAL EDYCJI -->
<div class="modal-bg" id="editModal">
  <div class="modal">
    <h3>Edycja Danych Hosta / Znaleziska</h3>
    <p style="font-size:12px; color:var(--muted);">Zmiany są szyfrowane i trwale zapamiętywane dla kolejnych skanów tego IP.</p>
    <input type="hidden" id="editFindingId"><input type="hidden" id="editFindingIp">
    <label>Hostname (Nadpisanie)</label><input id="editHostname">
    <label>Klasyfikacja środowiska</label>
    <select id="editEnv"><option>PROD/STANDARD</option><option>STAGING / TEST</option><option>PANEL ADMINA</option><option>INFRASTRUKTURA KRYTYCZNA</option></select>
    <label>Status znaleziska</label>
    <select id="editStatus"><option>ACTIVE</option><option>FALSE_POSITIVE</option><option>ACCEPTED_RISK</option></select>
    <label>Notatki analityka</label><textarea id="editNotes" rows="3"></textarea>
    <div style="margin-top:14px; display:flex; gap:10px; justify-content:flex-end;">
      <button class="sec" onclick="closeEditModal()">Anuluj</button>
      <button onclick="saveFindingEdit()">Zapisz zmiany</button>
    </div>
  </div>
</div>

<script>
let TOKEN = localStorage.getItem("proculus_token") || "";
let CURRENT_USER = null;
let FINDINGS_CACHE = [];
let NET_PRESETS = [];
let LAST_SUMMARY = null;
let IS_SCANNING_ACTIVE = false;
let LATEST_PROGRESS = null;
let VISUAL_PCT = 0;
let TARGET_PCT = 0;

const MODE_META = {
  fast:     { label: "Szybki Discovery", ports: [22, 80, 443, 8080, 8443], overhead: 1.05 },
  balanced: { label: "Zbalansowany",     ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443, 9000], overhead: 1.25 },
  deep:     { label: "Głęboki Recon",    ports: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017], overhead: 1.55 },
  stealth:  { label: "Ostrożny / Low-Noise", ports: [80, 443, 8080, 8443], overhead: 1.15 }
};

// ============================================================================
// 1. DYMKI PODPOWIEDZI PO NAJECHANIU (TOOLTIPS)
// ============================================================================
const tooltipEl = document.getElementById("hoverTooltip");
document.addEventListener("mouseover", (e) => {
  const target = e.target.closest("[data-tip]");
  if (!target) { tooltipEl.style.display = "none"; return; }
  const title = target.getAttribute("data-tip-title") || "Informacja";
  const text = target.getAttribute("data-tip");
  tooltipEl.innerHTML = `<b>${title}</b>${text}`;
  tooltipEl.style.display = "block";
});
document.addEventListener("mousemove", (e) => {
  if (tooltipEl.style.display === "block") {
    let x = e.clientX + 16;
    let y = e.clientY + 16;
    if (x + 350 > window.innerWidth) x = e.clientX - 355;
    if (y + 120 > window.innerHeight) y = e.clientY - 110;
    tooltipEl.style.left = x + "px";
    tooltipEl.style.top = y + "px";
  }
});

// ============================================================================
// 2. KALKULATOR PRZEWIDYWANEGO CZASU KAŻDEGO RODZAJU SKANOWANIA
// ============================================================================
function estimateTargetHostsCount() {
  const idx = parseInt(document.getElementById("targetPresetSelect").value || "0");
  const preset = NET_PRESETS[idx];
  if (!preset) return 1;
  if (preset.value !== "__CUSTOM__") {
    return preset.hosts_count || 1;
  }
  const raw = (document.getElementById("customTargetInput").value || "").trim();
  if (!raw) return 1;
  let total = 0;
  for (const part of raw.split(",")) {
    const item = part.trim();
    if (!item) continue;
    if (item.includes("/")) {
      const mask = parseInt(item.split("/")[1]);
      if (!isNaN(mask) && mask >= 8 && mask <= 32) {
        total += mask >= 31 ? 1 : Math.max(1, Math.pow(2, 32 - mask) - 2);
      } else {
        total += 254;
      }
    } else if (item.includes("-") && !/[a-zA-Z]/.test(item)) {
      const [a, b] = item.split("-");
      const lastA = parseInt((a.split(".")[3] || "1"));
      const lastB = parseInt((b.split(".")[3] || "1"));
      total += Math.max(1, Math.abs(lastB - lastA) + 1);
    } else {
      total += 1;
    }
  }
  return Math.max(1, total);
}

function formatDurationPl(seconds) {
  if (seconds < 1) return "< 1 sek.";
  if (seconds < 60) return `~${Math.round(seconds)} sek.`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return secs > 0 ? `~${mins} min ${secs} sek.` : `~${mins} min`;
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `~${hrs} godz. ${remMins} min`;
}

function updateTimeEstimates() {
  const hosts = estimateTargetHostsCount();
  let rateVal = document.getElementById("scanRate").value;
  if (rateVal === "__CUSTOM__") rateVal = document.getElementById("customRateInput").value || "150";
  const rate = Math.max(1, parseInt(rateVal) || 150);

  document.getElementById("estHostCountLabel").innerText = `Cel: ${hosts.toLocaleString("pl-PL")} ${hosts === 1 ? "host" : "hostów"}`;

  const sel = document.getElementById("scanMode");
  const currentMode = sel.value || "balanced";

  sel.innerHTML = Object.entries(MODE_META).map(([key, meta]) => {
    const estSec = ((hosts * meta.ports.length) / rate) * meta.overhead + (hosts === 1 ? 0.4 : 1.0);
    return `<option value="${key}" ${key === currentMode ? "selected" : ""}>${meta.label} (${meta.ports.length} portów) — ${formatDurationPl(estSec)}</option>`;
  }).join("");

  const grid = document.getElementById("etaModesGrid");
  grid.innerHTML = Object.entries(MODE_META).map(([key, meta]) => {
    const estSec = ((hosts * meta.ports.length) / rate) * meta.overhead + (hosts === 1 ? 0.4 : 1.0);
    const activeCls = key === currentMode ? "active-mode" : "";
    return `<div class="eta-item ${activeCls}"><span>${meta.label} (${meta.ports.length}p)</span><b class="mono" style="color:var(--accent);">${formatDurationPl(estSec)}</b></div>`;
  }).join("");
}

// ============================================================================
// 3. INTERAKTYWNY PRZEWODNIK PROCULUS
// ============================================================================
const TOUR_STEPS = [
  {
    el: "#field-target-wrap",
    text: "Witaj w systemie <b>Proculus</b>! Automatycznie wykryłem adres IP Twojego komputera i przygotowałem gotowe zakresy sieciowe do wyboru (np. lokalną podsieć <b>/24</b> lub bramę sieciową). Możesz też wybrać ostatnią opcję i wpisać dowolny cel ręcznie."
  },
  {
    el: "#field-eta-wrap",
    text: "Tutaj na bieżąco obliczam <b>przewidywany czas każdego rodzaju skanowania</b> (Szybki, Zbalansowany, Głęboki, Ostrożny) w oparciu o liczbę hostów w wybranym celu oraz ustawiony limit zapytań na sekundę."
  },
  {
    el: "#field-chunk-wrap",
    text: "Podział na <b>podgrupy (Chunk Size)</b> pozwala bezpiecznie skanować rozległe sieci powyżej <b>10 000 adresów IP</b>. Po każdej paczce wyniki są szyfrowane i zapisywane w bazie."
  },
  {
    el: "#tour-start-btn",
    text: "Kliknij <b>▶ Uruchom Skanowanie</b>, aby rozpocząć analizę. Najedź kursorem na dowolny element interfejsu, aby wyświetlić podpowiedź kontekstową."
  },
  {
    el: "#tour-progress",
    text: "W tym panelu zobaczysz <b>4 etapy skanowania</b> oraz wizualizację na żywo, jak silnik Proculus przechodzi przez konkretne <b>adresy IP i numery portów</b> (niebieski = aktywna sonda, zielony = otwarta usługa)."
  },
  {
    el: "#tour-summary",
    text: "Po zakończeniu skanu wygeneruję tutaj pełne <b>podsumowanie</b>. Jednym kliknięciem zapiszesz je do pliku <b>.TXT</b> lub wyczyścisz widok pod kolejny skan."
  }
];
let currentTourIdx = 0;

function startTour(force=false) {
  if (!force && localStorage.getItem("proculus_tour_done") === "1") return;
  currentTourIdx = 0;
  document.getElementById("tourBackdrop").style.display = "block";
  document.getElementById("mascotBox").style.display = "block";
  renderTourStep();
}

function renderTourStep() {
  document.querySelectorAll(".tour-highlight").forEach(el => el.classList.remove("tour-highlight"));
  const step = TOUR_STEPS[currentTourIdx];
  const target = document.querySelector(step.el);
  document.getElementById("tourStepCounter").innerText = `Krok ${currentTourIdx + 1} z ${TOUR_STEPS.length}`;
  document.getElementById("tourText").innerHTML = step.text;
  document.getElementById("tourPrevBtn").disabled = (currentTourIdx === 0);
  document.getElementById("tourNextBtn").innerText = (currentTourIdx === TOUR_STEPS.length - 1) ? "Zakończ ✔" : "Dalej ▶";

  if (target) {
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.classList.add("tour-highlight");
    const rect = target.getBoundingClientRect();
    const box = document.getElementById("mascotBox");
    const arrow = document.getElementById("mascotArrow");

    let left = rect.right + 28;
    let top = Math.max(20, rect.top);
    arrow.style.display = "block";
    arrow.innerText = "👈";
    arrow.style.left = "-34px";
    arrow.style.right = "auto";
    arrow.style.top = "24px";

    if (left + 410 > window.innerWidth) {
      left = Math.max(16, rect.left - 425);
      arrow.innerText = "👉";
      arrow.style.left = "auto";
      arrow.style.right = "-34px";
    }
    if (rect.width > window.innerWidth * 0.65) {
      left = Math.max(20, rect.left + 30);
      top = Math.max(20, rect.top - 210);
      arrow.innerText = "👇";
      arrow.style.left = "40px";
      arrow.style.top = "auto";
      arrow.style.bottom = "-30px";
    }
    box.style.left = left + "px";
    box.style.top = Math.min(window.innerHeight - 235, top) + "px";
  }
}

function nextTourStep() {
  if (currentTourIdx + 1 < TOUR_STEPS.length) {
    currentTourIdx++;
    renderTourStep();
  } else {
    endTour();
  }
}
function prevTourStep() {
  if (currentTourIdx > 0) {
    currentTourIdx--;
    renderTourStep();
  }
}
function endTour() {
  document.querySelectorAll(".tour-highlight").forEach(el => el.classList.remove("tour-highlight"));
  document.getElementById("tourBackdrop").style.display = "none";
  document.getElementById("mascotBox").style.display = "none";
  localStorage.setItem("proculus_tour_done", "1");
}

// ============================================================================
// 4. WIZUALIZACJA PRZECHODZENIA PRZEZ HOSTY I PORTY NA ŻYWO (CANVAS)
// ============================================================================
(function initLiveTopologyVisualizer() {
  const canvas = document.getElementById("scanVizCanvas");
  const ctx = canvas.getContext("2d");
  let pulsePhase = 0;

  function resize() {
    canvas.width = canvas.parentElement.clientWidth || 640;
    canvas.height = 225;
  }
  window.addEventListener("resize", resize);
  resize();

  function drawRoundRect(x, y, w, h, r, fill, stroke, lineWidth=1) {
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, r);
    if (fill) { ctx.fillStyle = fill; ctx.fill(); }
    if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = lineWidth; ctx.stroke(); }
  }

  function render() {
    pulsePhase = (pulsePhase + 0.04) % 1;
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Subtelna siatka techniczna w tle
    ctx.strokeStyle = "rgba(0, 119, 230, 0.06)";
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 32) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let y = 0; y < H; y += 32) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }

    const p = LATEST_PROGRESS;
    const modeKey = document.getElementById("scanMode") ? document.getElementById("scanMode").value : "balanced";
    const portsToShow = (p && p.mode_ports && p.mode_ports.length) ? p.mode_ports : (MODE_META[modeKey]?.ports || [22, 80, 443, 8080, 8443]);

    // 1. LEWY WĘZEŁ: SILNIK PROCULUS
    const engX = 18, engY = H / 2 - 36, engW = 122, engH = 72;
    drawRoundRect(engX, engY, engW, engH, 10, "#ffffff", IS_SCANNING_ACTIVE ? "#0077e6" : "#cbd5e1", IS_SCANNING_ACTIVE ? 2 : 1.2);
    ctx.fillStyle = "#0077e6";
    ctx.font = "bold 12px 'Segoe UI', sans-serif";
    ctx.fillText("PROCULUS", engX + 26, engY + 26);
    ctx.fillStyle = "#475569";
    ctx.font = "10.5px Consolas, monospace";
    ctx.fillText(IS_SCANNING_ACTIVE ? "SCANNING..." : "ENGINE READY", engX + 20, engY + 43);
    ctx.fillStyle = "#0ea5e9";
    ctx.fillText(p ? `CHUNK ${p.current_chunk}/${p.total_chunks}` : "MULTI-THREAD", engX + 20, engY + 58);

    // 2. ŚRODKOWA KOLUMNA: FAKTYCZNE HOSTY (ADRESY IP)
    const liveHosts = (p && p.live_hosts && p.live_hosts.length) ? p.live_hosts.slice(-5) : [];
    const hostColX = Math.max(165, W * 0.30);
    const hostW = 148;
    const hostH = 30;

    if (liveHosts.length === 0) {
      drawRoundRect(hostColX, H / 2 - 20, hostW, 40, 8, "#ffffff", "#cbd5e1", 1);
      ctx.fillStyle = "#64748b";
      ctx.font = "11px Consolas, monospace";
      ctx.fillText("Oczekiwanie na cele...", hostColX + 12, H / 2 + 4);
    } else {
      const totalH = liveHosts.length * (hostH + 8) - 8;
      const startY = Math.max(12, (H - totalH) / 2);

      liveHosts.forEach((h, idx) => {
        const hy = startY + idx * (hostH + 8);
        const isCurrent = (p && p.current_ip === h.ip && IS_SCANNING_ACTIVE);
        const isOnline = h.state === "ONLINE" || (h.open_ports && h.open_ports.length > 0);

        // Połączenie z silnikiem Proculus
        ctx.beginPath();
        ctx.moveTo(engX + engW, engY + engH / 2);
        ctx.bezierCurveTo(engX + engW + 30, engY + engH / 2, hostColX - 30, hy + hostH / 2, hostColX, hy + hostH / 2);
        ctx.strokeStyle = isCurrent ? "#0077e6" : (isOnline ? "#10b981" : "#cbd5e1");
        ctx.lineWidth = isCurrent ? 2.2 : 1.2;
        ctx.stroke();

        // Animowany impuls pakietu wzdłuż linii
        if (isCurrent) {
          const px = (engX + engW) + (hostColX - (engX + engW)) * pulsePhase;
          const py = (engY + engH / 2) + ((hy + hostH / 2) - (engY + engH / 2)) * pulsePhase;
          ctx.beginPath();
          ctx.arc(px, py, 4, 0, Math.PI * 2);
          ctx.fillStyle = "#0077e6";
          ctx.fill();
        }

        const bg = isCurrent ? "#eff6ff" : (isOnline ? "#ecfdf5" : "#ffffff");
        const brd = isCurrent ? "#0077e6" : (isOnline ? "#059669" : "#cbd5e1");
        drawRoundRect(hostColX, hy, hostW, hostH, 7, bg, brd, isCurrent ? 2 : 1.2);

        ctx.fillStyle = isCurrent ? "#0077e6" : (isOnline ? "#059669" : "#334155");
        ctx.font = "bold 11.5px Consolas, monospace";
        ctx.fillText(h.ip, hostColX + 10, hy + 19);

        const openCnt = (h.open_ports || []).length;
        if (openCnt > 0) {
          ctx.fillStyle = "#059669";
          ctx.font = "bold 10px 'Segoe UI', sans-serif";
          ctx.fillText(`${openCnt} OPEN`, hostColX + hostW - 46, hy + 18);
        }
      });
    }

    // 3. PRAWA SEKCJA: MACIERZ PORTÓW AKTYWNEGO HOSTA
    const portAreaX = hostColX + hostW + 34;
    const portAreaW = W - portAreaX - 16;
    if (portAreaW > 110) {
      const activeHostObj = liveHosts.find(h => p && h.ip === p.current_ip) || liveHosts[liveHosts.length - 1] || null;
      const activeIpTitle = activeHostObj ? activeHostObj.ip : "Podgląd portów trybu";

      ctx.fillStyle = "#0f172a";
      ctx.font = "bold 11px 'Segoe UI', sans-serif";
      ctx.fillText(`PORTY: ${activeIpTitle}`, portAreaX, 18);

      const cols = Math.max(3, Math.min(6, Math.floor(portAreaW / 56)));
      const cellW = Math.floor((portAreaW - (cols - 1) * 6) / cols);
      const cellH = 22;
      const visiblePorts = portsToShow.slice(0, cols * 7);

      visiblePorts.forEach((portNum, i) => {
        const c = i % cols;
        const r = Math.floor(i / cols);
        const px = portAreaX + c * (cellW + 6);
        const py = 26 + r * (cellH + 5);

        const isProbing = IS_SCANNING_ACTIVE && p && p.current_port === portNum;
        const isOpen = activeHostObj && (activeHostObj.open_ports || []).some(op => op.port === portNum);
        const isScanned = activeHostObj && (activeHostObj.scanned_ports || []).includes(portNum);

        let fill = "#ffffff", stroke = "#cbd5e1", txtCol = "#475569";
        if (isProbing) {
          fill = "#0077e6"; stroke = "#005bb5"; txtCol = "#ffffff";
          // Wiązka z aktywnego hosta do badanego portu
          ctx.beginPath();
          ctx.moveTo(hostColX + hostW, H / 2);
          ctx.lineTo(px, py + cellH / 2);
          ctx.strokeStyle = "rgba(0, 119, 230, 0.55)";
          ctx.lineWidth = 1.6;
          ctx.stroke();
        } else if (isOpen) {
          fill = "#10b981"; stroke = "#059669"; txtCol = "#ffffff";
        } else if (isScanned) {
          fill = "#f1f5f9"; stroke = "#e2e8f0"; txtCol = "#94a3b8";
        }

        drawRoundRect(px, py, cellW, cellH, 5, fill, stroke, 1);
        ctx.fillStyle = txtCol;
        ctx.font = "bold 10.5px Consolas, monospace";
        ctx.fillText(String(portNum), px + 6, py + 14);
      });
    }

    // Płynna interpolacja paska postępu (nigdy nie skacze i nie zacina się wizualnie)
    if (Math.abs(TARGET_PCT - VISUAL_PCT) > 0.05) {
      VISUAL_PCT += (TARGET_PCT - VISUAL_PCT) * 0.25;
      document.getElementById("progBar").style.width = VISUAL_PCT.toFixed(2) + "%";
    }

    requestAnimationFrame(render);
  }
  render();
})();

// ============================================================================
// 5. LOGIKA FORMULARZY, PRESETÓW I KOMUNIKACJI Z API
// ============================================================================
async function api(path, method="GET", body=null) {
  const opts = { method, headers: { "X-Auth-Token": TOKEN } };
  if (body !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    TOKEN = "";
    localStorage.removeItem("proculus_token");
    document.getElementById("appScreen").style.display = "none";
    document.getElementById("loginScreen").style.display = "block";
    throw new Error("Brak autoryzacji");
  }
  return await res.json();
}

async function doLogin() {
  const u = document.getElementById("loginUser").value;
  const p = document.getElementById("loginPass").value;
  const res = await fetch("/api/login", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ username: u, password: p })
  });
  const data = await res.json();
  if (data.ok) {
    TOKEN = data.token;
    localStorage.setItem("proculus_token", TOKEN);
    initApp();
  } else {
    document.getElementById("loginErr").innerText = data.error || "Błąd logowania";
  }
}

function doLogout() {
  TOKEN = "";
  localStorage.removeItem("proculus_token");
  location.reload();
}

let pollTimer = null;
let pollInFlight = false;

async function initApp() {
  if (!TOKEN) return;
  try {
    const me = await api("/api/me");
    if (!me.ok) return;
    CURRENT_USER = me.user;
    document.getElementById("loginScreen").style.display = "none";
    document.getElementById("appScreen").style.display = "block";
    document.getElementById("uiUser").innerText = CURRENT_USER.username;
    document.getElementById("uiRole").innerText = CURRENT_USER.role;

    const perms = CURRENT_USER.perms;
    document.getElementById("tabBtnAdmin").style.display = perms.admin ? "inline-block" : "none";
    document.getElementById("btnStartScan").disabled = !perms.modify;
    document.getElementById("btnStopScan").disabled = !perms.modify;

    await loadNetworkPresets();
    await refreshAll();
    if (!pollTimer) {
      pollTimer = setInterval(pollProgress, 320);
    }
    setTimeout(() => startTour(false), 450);
  } catch (e) {}
}

async function loadNetworkPresets() {
  const data = await api("/api/network_presets");
  NET_PRESETS = data.presets || [];
  document.getElementById("detectedNetBadge").innerText = `Twoje IP: ${data.primary_ip}`;
  const sel = document.getElementById("targetPresetSelect");
  sel.innerHTML = NET_PRESETS.map((p, idx) => `<option value="${idx}">${p.label}</option>`).join("");
  onTargetPresetChange();
}

function onTargetPresetChange() {
  const idx = parseInt(document.getElementById("targetPresetSelect").value || "0");
  const preset = NET_PRESETS[idx];
  if (!preset) return;
  document.getElementById("presetDescBox").innerText = "ℹ " + preset.desc;
  const isCustom = preset.value === "__CUSTOM__";
  document.getElementById("customTargetBox").style.display = isCustom ? "block" : "none";
  updateTimeEstimates();
}

function toggleCustomNumeric(selId, inpId) {
  const val = document.getElementById(selId).value;
  document.getElementById(inpId).style.display = (val === "__CUSTOM__") ? "block" : "none";
}

function onWinPresetChange() {
  const val = document.getElementById("winPreset").value;
  document.getElementById("customWinBox").style.display = (val === "__CUSTOM__") ? "grid" : "none";
  if (val !== "__CUSTOM__") {
    const [s, e] = val.split("|");
    document.getElementById("winStart").value = s;
    document.getElementById("winEnd").value = e;
  }
}

function openTab(name, btn) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("view-" + name).classList.add("active");
  btn.classList.add("active");
}

async function refreshAll() {
  await loadScansList();
  await loadTargets();
  await loadSignatures();
  await loadSchedule();
  await loadStability();
  if (CURRENT_USER && CURRENT_USER.perms.admin) await loadUsers();
}

function updateStagePills(stageNum, isRunning, isFinished) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById("stagePill" + i);
    el.classList.remove("active", "done");
    if (isFinished) {
      el.classList.add("done");
    } else if (isRunning) {
      if (i < stageNum) el.classList.add("done");
      else if (i === stageNum) el.classList.add("active");
    }
  }
}

async function pollProgress() {
  if (!TOKEN || pollInFlight) return;
  pollInFlight = true;
  try {
    const p = await api("/api/progress");
    LATEST_PROGRESS = p;
    const wasScanning = IS_SCANNING_ACTIVE;
    IS_SCANNING_ACTIVE = !!p.running;

    // Pasek postępu oparty na liczbie sond (hosty * porty) - płynny przy każdym zakresie!
    const totalProbes = Math.max(1, p.total_probes || 1);
    const doneProbes = Math.min(totalProbes, p.completed_probes || 0);
    const exactPct = p.total_ips > 0 ? Math.min(100, (doneProbes / totalProbes) * 100) : 0;
    TARGET_PCT = exactPct;
    if (!p.running && exactPct === 0) {
      VISUAL_PCT = 0;
      document.getElementById("progBar").style.width = "0%";
    }

    document.getElementById("progStatus").innerText = p.status_text;
    document.getElementById("progNumbers").innerText = `${exactPct.toFixed(1)}% (${doneProbes}/${totalProbes} sond)`;
    document.getElementById("progHostsDone").innerText = `${p.scanned_ips}/${p.total_ips}`;
    document.getElementById("progChunk").innerText = `${p.current_chunk}/${p.total_chunks}`;
    document.getElementById("progTime").innerText = `${p.elapsed_sec}s`;
    document.getElementById("progEta").innerText = p.running ? `${p.eta_sec}s` : "-";
    document.getElementById("progSpeed").innerText = `${p.probes_per_sec || 0} sond/s`;

    // Aktualizacja wizualizacji etapów oraz paska telemetrii
    const isFinished = !p.running && !!p.last_summary;
    updateStagePills(p.current_stage || 0, p.running, isFinished);

    const dot = document.getElementById("vizDot");
    if (p.running) dot.classList.add("live"); else dot.classList.remove("live");

    document.getElementById("vizLiveTarget").innerText = p.running
      ? `SKAN: ${p.current_ip}:${p.current_port} (${p.current_service})`
      : (isFinished ? `ZAKOŃCZONO: ${p.target_label}` : "CEL: Oczekiwanie na start");
    document.getElementById("vizStageLabel").innerText = p.stage_label || "ETAP: IDLE";

    if (p.running) {
      document.getElementById("kpiHosts").innerText = p.active_hosts;
      document.getElementById("kpiServices").innerText = p.findings_count;
    }

    const box = document.getElementById("progLogs");
    box.innerHTML = (p.logs || []).map(l => `<div>${l}</div>`).join("");
    box.scrollTop = box.scrollHeight;

    if (p.last_summary) {
      LAST_SUMMARY = p.last_summary;
      renderSummaryBox(p.last_summary);
    }

    if (wasScanning && !p.running) {
      await refreshAll();
    }
  } catch (e) {
  } finally {
    pollInFlight = false;
  }
}

function renderSummaryBox(s) {
  document.getElementById("btnSaveTxt").disabled = false;
  const lines = [
    `====================================================================`,
    ` RAPORT PODSUMOWUJĄCY SKANOWANIE — PROCULUS (CBI AGH)`,
    `====================================================================`,
    ` ID Skanu         : #${s.scan_id} (${s.status})`,
    ` Skanowany cel    : ${s.target}`,
    ` Wybrany tryb     : ${s.mode}`,
    ` Czas rozpoczęcia : ${s.started_at} | Zakończenia: ${s.finished_at} (${s.duration_sec}s)`,
    ` Przeskanowano IP : ${s.scanned_ips} z ${s.total_ips}`,
    ` Aktywne hosty    : ${s.active_hosts_count} (${(s.active_hosts_list || []).join(", ") || "brak"})`,
    ` Wykryte usługi   : ${s.services_count} (w tym panele/ciekawe: ${s.interesting_count})`,
    `--------------------------------------------------------------------`,
    ` WYKRYTE USŁUGI, TECHNOLOGIE I SYGNATURY:`,
    ...(s.highlights && s.highlights.length ? s.highlights.map((h, i) => `  ${i+1}. ${h}`) : ["  Brak otwartych usług w badanym zakresie."]),
    `====================================================================`
  ];
  document.getElementById("summaryContent").innerText = lines.join("\n");
}

function downloadSummaryTxt() {
  if (!LAST_SUMMARY) return;
  const text = document.getElementById("summaryContent").innerText;
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `proculus_raport_${LAST_SUMMARY.scan_id}_${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
}

async function resetForNewScan() {
  await api("/api/scan/clear_status", "POST", {});
  LAST_SUMMARY = null;
  LATEST_PROGRESS = null;
  TARGET_PCT = 0;
  VISUAL_PCT = 0;
  document.getElementById("btnSaveTxt").disabled = true;
  document.getElementById("summaryContent").innerText = "Wyczyszczono podsumowanie. Wybierz nową sieć powyżej i kliknij „Uruchom Skanowanie”.";
  document.getElementById("progBar").style.width = "0%";
  document.getElementById("progNumbers").innerText = "0% (0 / 0 sond)";
  document.getElementById("progStatus").innerText = "Gotowy do nowego skanu";
  document.getElementById("progLogs").innerHTML = "";
  updateStagePills(0, false, false);
}

async function startScan() {
  const idx = parseInt(document.getElementById("targetPresetSelect").value || "0");
  const preset = NET_PRESETS[idx];
  let targetList = [];
  if (preset && preset.value === "__CUSTOM__") {
    const raw = document.getElementById("customTargetInput").value.trim();
    if (!raw) { alert("Wpisz adres IP, maskę CIDR lub domenę!"); return; }
    targetList = raw.split(",").map(s => s.trim());
  } else if (preset) {
    targetList = [preset.value];
  }

  let rateVal = document.getElementById("scanRate").value;
  if (rateVal === "__CUSTOM__") rateVal = document.getElementById("customRateInput").value || "150";

  let chunkVal = document.getElementById("scanChunk").value;
  if (chunkVal === "__CUSTOM__") chunkVal = document.getElementById("customChunkInput").value || "64";

  TARGET_PCT = 0;
  VISUAL_PCT = 0;
  document.getElementById("progBar").style.width = "0%";

  const payload = {
    mode: document.getElementById("scanMode").value,
    rate_limit: parseInt(rateVal),
    chunk_size: parseInt(chunkVal),
    offline_threshold: parseInt(document.getElementById("scanOfflineThresh").value || "3"),
    win_start: document.getElementById("winStart").value,
    win_end: document.getElementById("winEnd").value,
    custom_targets: targetList
  };
  const res = await api("/api/scan/start", "POST", payload);
  if (!res.ok) alert(res.error);
}

async function stopScan() { await api("/api/scan/stop", "POST", {}); }

async function loadScansList() {
  const data = await api("/api/scans");
  const scans = data.scans || [];
  const opts = scans.map(s => `<option value="${s.id}">Skan #${s.id} (${s.started_at}) [${s.status}]</option>`).join("");
  document.getElementById("selectScanView").innerHTML = opts;
  document.getElementById("diffScanA").innerHTML = opts;
  document.getElementById("diffScanB").innerHTML = opts;
  if (scans.length > 1) document.getElementById("diffScanA").selectedIndex = 1;
  if (scans.length > 0) await loadFindings();
}

async function loadFindings() {
  const sid = document.getElementById("selectScanView").value;
  if (!sid) return;
  const data = await api(`/api/findings?scan_id=${sid}`);
  FINDINGS_CACHE = data.findings || [];

  const uniqueHosts = new Set(FINDINGS_CACHE.map(f => f.ip));
  const interesting = FINDINGS_CACHE.filter(f => f.environment_tag !== "PROD/STANDARD").length;
  document.getElementById("kpiHosts").innerText = uniqueHosts.size;
  document.getElementById("kpiServices").innerText = FINDINGS_CACHE.length;
  document.getElementById("kpiInteresting").innerText = interesting;
  renderFindingsTable();
}

function renderFindingsTable() {
  const q = document.getElementById("filterInput").value.toLowerCase();
  const canEdit = CURRENT_USER && CURRENT_USER.perms.modify;
  const filtered = FINDINGS_CACHE.filter(f => JSON.stringify(f).toLowerCase().includes(q));
  document.getElementById("findingsBody").innerHTML = filtered.map(f => `
    <tr>
      <td class="mono"><b>${f.ip}</b><br><span style="color:var(--muted)">${f.hostname || '-'}</span></td>
      <td class="mono"><span class="badge b-blue">${f.port}/${f.protocol}</span><br>${f.service}</td>
      <td>${f.http_status ? `<b>HTTP ${f.http_status}</b>: ${f.http_title || '(brak tytułu)'}` : '-'}
          ${f.redirect ? `<br><span style="color:var(--warn)">-> ${f.redirect}</span>` : ''}</td>
      <td><span class="badge ${f.environment_tag === 'PROD/STANDARD' ? 'b-green' : 'b-warn'}">${f.environment_tag}</span><br>
          <span style="font-size:11.5px;">${f.technologies || ''}</span>
          ${f.matched_signatures ? `<br><span style="color:var(--danger); font-size:11px;">${f.matched_signatures}</span>` : ''}</td>
      <td style="font-size:11px; max-width:240px;">
        ${f.tls_info ? `<div><b>TLS:</b> ${f.tls_info}</div>` : ''}
        ${f.cookies ? `<div><b>Cookies:</b> ${f.cookies.slice(0,80)}</div>` : ''}
        ${f.headers ? `<div style="color:var(--muted)">${f.headers.slice(0,90)}...</div>` : ''}
      </td>
      <td><b>${f.confidence}%</b></td>
      <td>${f.analyst_notes || ''}<br><span class="badge b-blue">${f.custom_status}</span></td>
      <td>${canEdit ? `<button class="sec" onclick='openEditModal(${JSON.stringify(f)})'>Edytuj</button>` : '-'}</td>
    </tr>
  `).join("");
}

function openEditModal(f) {
  document.getElementById("editFindingId").value = f.id;
  document.getElementById("editFindingIp").value = f.ip;
  document.getElementById("editHostname").value = f.hostname || "";
  document.getElementById("editEnv").value = f.environment_tag || "PROD/STANDARD";
  document.getElementById("editStatus").value = f.custom_status || "ACTIVE";
  document.getElementById("editNotes").value = f.analyst_notes || "";
  document.getElementById("editModal").style.display = "flex";
}
function closeEditModal() { document.getElementById("editModal").style.display = "none"; }

async function saveFindingEdit() {
  const payload = {
    id: parseInt(document.getElementById("editFindingId").value),
    ip: document.getElementById("editFindingIp").value,
    hostname: document.getElementById("editHostname").value,
    environment_tag: document.getElementById("editEnv").value,
    custom_status: document.getElementById("editStatus").value,
    analyst_notes: document.getElementById("editNotes").value
  };
  const res = await api("/api/findings/update", "POST", payload);
  if (res.ok) { closeEditModal(); await loadFindings(); }
  else alert(res.error);
}

async function loadStability() {
  const data = await api("/api/stability");
  const rows = data.hosts || [];
  document.getElementById("kpiUnstable").innerText = rows.filter(r => r.state !== "ONLINE").length;
  document.getElementById("stabilityBody").innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${r.ip}</td>
      <td><span class="badge ${r.state === 'ONLINE' ? 'b-green' : (r.state === 'OFFLINE' ? 'b-red' : 'b-warn')}">${r.state}</span></td>
      <td>${r.seen_count}</td><td>${r.missed_streak}</td><td class="mono">${r.last_seen}</td>
    </tr>
  `).join("");
}

async function runDiff() {
  const a = document.getElementById("diffScanA").value;
  const b = document.getElementById("diffScanB").value;
  const res = await api(`/api/diff?scan_a=${a}&scan_b=${b}`);
  document.getElementById("diffAdded").innerHTML = (res.added || []).map(x => `<tr><td class="mono">${x.ip}:${x.port}</td><td>${x.service}</td><td>${x.technologies}</td></tr>`).join("");
  document.getElementById("diffRemoved").innerHTML = (res.removed || []).map(x => `<tr><td class="mono">${x.ip}:${x.port}</td><td>${x.service}</td><td>${x.technologies}</td></tr>`).join("");
  document.getElementById("diffChanged").innerHTML = (res.changed || []).map(x => `<tr><td class="mono">${x.ip}:${x.port}</td><td>${x.changes}</td></tr>`).join("");
}

async function loadTargets() {
  const data = await api("/api/targets");
  const canDel = CURRENT_USER && CURRENT_USER.perms.add_delete;
  document.getElementById("targetsBody").innerHTML = (data.targets || []).map(t => `
    <tr><td>${t.id}</td><td class="mono"><b>${t.target}</b></td><td>${t.label}</td><td>${t.tags}</td>
    <td>${canDel ? `<button class="danger" onclick="delTarget(${t.id})">Usuń</button>` : '-'}</td></tr>
  `).join("");
}

async function addTarget() {
  const res = await api("/api/targets", "POST", {
    target: document.getElementById("newTargetVal").value,
    label: document.getElementById("newTargetLabel").value,
    tags: document.getElementById("newTargetTags").value
  });
  if (res.ok) { document.getElementById("newTargetVal").value = ""; loadTargets(); }
  else alert(res.error);
}
async function delTarget(id) { await api("/api/targets/delete", "POST", { id }); loadTargets(); }

async function importTargetsFile() {
  const f = document.getElementById("targetFileInput").files[0];
  if (!f) return;
  const res = await api("/api/targets/import", "POST", { filename: f.name, content: await f.text() });
  alert(res.message || res.error);
  loadTargets();
}

function exportData(fmt) {
  const sid = document.getElementById("selectScanView").value;
  window.open(`/api/export?scan_id=${sid}&format=${fmt}&token=${TOKEN}`, "_blank");
}

async function importFindings(inp) {
  const f = inp.files[0];
  if (!f) return;
  const res = await api("/api/findings/import", "POST", { filename: f.name, content: await f.text() });
  alert(res.message || res.error);
  await loadScansList();
}

async function loadSignatures() {
  const data = await api("/api/signatures");
  const canDel = CURRENT_USER && CURRENT_USER.perms.add_delete;
  document.getElementById("sigsBody").innerHTML = (data.signatures || []).map(s => `
    <tr><td><b>${s.name}</b></td><td>${s.category}</td><td>${s.match_type}</td>
    <td class="mono">${s.pattern}</td><td><span class="badge b-warn">${s.severity}</span></td>
    <td>${canDel ? `<button class="danger" onclick="delSig(${s.id})">Usuń</button>` : '-'}</td></tr>
  `).join("");
}

async function addSignature() {
  const res = await api("/api/signatures", "POST", {
    name: document.getElementById("sigName").value,
    category: document.getElementById("sigCat").value,
    match_type: document.getElementById("sigType").value,
    pattern: document.getElementById("sigPattern").value,
    severity: document.getElementById("sigSev").value
  });
  if (res.ok) loadSignatures(); else alert(res.error);
}
async function delSig(id) { await api("/api/signatures/delete", "POST", { id }); loadSignatures(); }

async function loadSchedule() {
  const data = await api("/api/schedule");
  if (!data.schedule) return;
  const s = data.schedule;
  document.getElementById("schedInterval").value = s.interval_minutes;
  document.getElementById("schedStart").value = s.window_start;
  document.getElementById("schedEnd").value = s.window_end;
  document.getElementById("schedMode").value = s.mode;
  document.getElementById("schedRate").value = s.rate_limit;
  document.getElementById("schedEnabled").value = String(s.enabled);
}

async function saveSchedule() {
  const res = await api("/api/schedule", "POST", {
    interval_minutes: parseInt(document.getElementById("schedInterval").value),
    window_start: document.getElementById("schedStart").value,
    window_end: document.getElementById("schedEnd").value,
    mode: document.getElementById("schedMode").value,
    rate_limit: parseInt(document.getElementById("schedRate").value),
    enabled: parseInt(document.getElementById("schedEnabled").value)
  });
  alert(res.ok ? "Zapisano harmonogram." : res.error);
}

async function sendDefectDojo() {
  const sid = document.getElementById("selectScanView").value;
  const res = await api("/api/defectdojo", "POST", {
    scan_id: parseInt(sid),
    url: document.getElementById("ddUrl").value,
    token: document.getElementById("ddToken").value,
    engagement_id: parseInt(document.getElementById("ddEngagement").value)
  });
  document.getElementById("ddMsg").innerText = res.message || res.error;
}

async function loadUsers() {
  const data = await api("/api/users");
  document.getElementById("usersBody").innerHTML = (data.users || []).map(u => `
    <tr><td>${u.id}</td><td><b>${u.username}</b></td><td>${u.role}</td>
    <td>${u.username !== 'admin' ? `<button class="danger" onclick="delUser(${u.id})">Usuń</button>` : '-'}</td></tr>
  `).join("");
}

async function createUser() {
  const res = await api("/api/users", "POST", {
    username: document.getElementById("newUsername").value,
    password: document.getElementById("newUserPass").value,
    role: document.getElementById("newUserRole").value
  });
  if (res.ok) loadUsers(); else alert(res.error);
}
async function delUser(id) { await api("/api/users/delete", "POST", { id }); loadUsers(); }

updateTimeEstimates();
initApp();
</script>
</body>
</html>
"""


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, obj, status=200):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _auth_user(self, query_token=""):
        token = self.headers.get("X-Auth-Token", "") or query_token
        return SESSIONS.get(token)

    def _require_perm(self, perm: str):
        u = self._auth_user()
        if not u:
            self._send_json({"ok": False, "error": "Wymagane logowanie."}, 401)
            return None
        if not ROLES.get(u["role"], {}).get(perm, False):
            self._send_json({"ok": False, "error": f"Brak uprawnień dla roli '{u['role']}'."}, 403)
            return None
        return u

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/api/health":
            return self._send_json({"ok": True, "app": "Proculus"})

        if path == "/":
            raw = HTML_APP.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/me":
            u = self._auth_user()
            if not u:
                return self._send_json({"ok": False}, 401)
            return self._send_json({"ok": True, "user": {**u, "perms": ROLES[u["role"]]}})

        if path == "/api/network_presets":
            if not self._require_perm("read"):
                return
            return self._send_json(detect_local_network_presets())

        if path == "/api/progress":
            if not self._require_perm("read"):
                return
            with SCANNER.lock:
                return self._send_json(dict(SCANNER.progress))

        if path == "/api/scans":
            if not self._require_perm("read"):
                return
            with db_lock:
                conn = get_db()
                rows = [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()]
                conn.close()
            return self._send_json({"scans": rows})

        if path == "/api/findings":
            if not self._require_perm("read"):
                return
            sid = int(qs.get("scan_id", [0])[0])
            return self._send_json({"findings": get_decrypted_findings(sid)})

        if path == "/api/stability":
            if not self._require_perm("read"):
                return
            with db_lock:
                conn = get_db()
                rows = conn.execute("SELECT * FROM host_stability ORDER BY last_seen DESC").fetchall()
                conn.close()
            hosts = [{
                "ip": AtRestCipher.decrypt(r["ip_enc"]),
                "seen_count": r["seen_count"],
                "missed_streak": r["missed_streak"],
                "last_seen": r["last_seen"],
                "state": r["state"]
            } for r in rows]
            return self._send_json({"hosts": hosts})

        if path == "/api/diff":
            if not self._require_perm("read"):
                return
            sa = int(qs.get("scan_a", [0])[0])
            sb = int(qs.get("scan_b", [0])[0])
            return self._send_json(compare_scans(sa, sb))

        if path == "/api/targets":
            if not self._require_perm("read"):
                return
            with db_lock:
                conn = get_db()
                rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
                conn.close()
            targets = [{
                "id": r["id"],
                "target": AtRestCipher.decrypt(r["target_enc"]),
                "label": r["label"],
                "tags": r["tags"]
            } for r in rows]
            return self._send_json({"targets": targets})

        if path == "/api/signatures":
            if not self._require_perm("read"):
                return
            with db_lock:
                conn = get_db()
                rows = [dict(r) for r in conn.execute("SELECT * FROM signatures ORDER BY id DESC").fetchall()]
                conn.close()
            return self._send_json({"signatures": rows})

        if path == "/api/schedule":
            if not self._require_perm("read"):
                return
            with db_lock:
                conn = get_db()
                row = conn.execute("SELECT * FROM schedules LIMIT 1").fetchone()
                conn.close()
            return self._send_json({"schedule": dict(row) if row else None})

        if path == "/api/users":
            if not self._require_perm("admin"):
                return
            with db_lock:
                conn = get_db()
                rows = [dict(r) for r in conn.execute("SELECT id, username, role FROM users").fetchall()]
                conn.close()
            return self._send_json({"users": rows})

        if path == "/api/export":
            tok = qs.get("token", [""])[0]
            u = self._auth_user(tok)
            if not u:
                return self._send_json({"error": "Unauthorized"}, 401)
            sid = int(qs.get("scan_id", [0])[0])
            fmt = qs.get("format", ["json"])[0]
            items = get_decrypted_findings(sid)
            if fmt == "csv":
                buf = io.StringIO()
                fields = ["ip", "hostname", "port", "protocol", "service", "http_status", "http_title",
                          "technologies", "environment_tag", "matched_signatures", "tls_info", "confidence", "analyst_notes"]
                writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(items)
                raw = buf.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="proculus_scan_{sid}.csv"')
                self.end_headers()
                self.wfile.write(raw)
            else:
                raw = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="proculus_scan_{sid}.json"')
                self.end_headers()
                self.wfile.write(raw)
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        data = self._read_json()

        if path == "/api/login":
            uname = data.get("username", "").strip()
            pwd = data.get("password", "")
            with db_lock:
                conn = get_db()
                row = conn.execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()
                conn.close()
            if not row:
                return self._send_json({"ok": False, "error": "Nieprawidłowy login lub hasło."}, 401)
            calc = hashlib.pbkdf2_hmac("sha256", pwd.encode(), row["salt"].encode(), 100_000).hex()
            if not hmac.compare_digest(calc, row["password_hash"]):
                return self._send_json({"ok": False, "error": "Nieprawidłowy login lub hasło."}, 401)
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {"id": row["id"], "username": row["username"], "role": row["role"]}
            return self._send_json({"ok": True, "token": tok})

        if path == "/api/scan/start":
            if not self._require_perm("modify"):
                return
            ok, msg = SCANNER.start_scan(
                mode=data.get("mode", "balanced"),
                rate_limit=data.get("rate_limit", 150),
                chunk_size=data.get("chunk_size", 64),
                win_start=data.get("win_start", "00:00"),
                win_end=data.get("win_end", "23:59"),
                offline_threshold=data.get("offline_threshold", 3),
                custom_targets=data.get("custom_targets")
            )
            return self._send_json({"ok": ok, "error": None if ok else msg})

        if path == "/api/scan/stop":
            if not self._require_perm("modify"):
                return
            SCANNER.stop_scan()
            return self._send_json({"ok": True})

        if path == "/api/scan/clear_status":
            if not self._require_perm("read"):
                return
            SCANNER.clear_live_status()
            return self._send_json({"ok": True})

        if path == "/api/findings/update":
            if not self._require_perm("modify"):
                return
            fid = int(data.get("id", 0))
            ip_str = data.get("ip", "")
            h_hash = ip_digest(ip_str)
            now_iso = datetime.now().isoformat(timespec="seconds")
            with db_lock:
                conn = get_db()
                conn.execute("""
                    UPDATE findings SET hostname_enc = ?, environment_tag = ?, custom_status = ?, analyst_notes_enc = ?
                    WHERE id = ?
                """, (
                    AtRestCipher.encrypt(data.get("hostname", "")),
                    data.get("environment_tag", "PROD/STANDARD"),
                    data.get("custom_status", "ACTIVE"),
                    AtRestCipher.encrypt(data.get("analyst_notes", "")),
                    fid
                ))
                conn.execute("""
                    INSERT INTO host_overrides (ip_hash, ip_enc, custom_hostname_enc, custom_env, analyst_notes_enc, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip_hash) DO UPDATE SET
                        custom_hostname_enc = excluded.custom_hostname_enc,
                        custom_env = excluded.custom_env,
                        analyst_notes_enc = excluded.analyst_notes_enc,
                        updated_at = excluded.updated_at
                """, (
                    h_hash,
                    AtRestCipher.encrypt(ip_str),
                    AtRestCipher.encrypt(data.get("hostname", "")),
                    data.get("environment_tag", "PROD/STANDARD"),
                    AtRestCipher.encrypt(data.get("analyst_notes", "")),
                    now_iso
                ))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/findings/import":
            if not self._require_perm("add_delete"):
                return
            fname = data.get("filename", "")
            content = data.get("content", "")
            records = []
            try:
                if fname.lower().endswith(".json"):
                    records = json.loads(content)
                else:
                    records = list(csv.DictReader(io.StringIO(content)))
            except Exception as e:
                return self._send_json({"ok": False, "error": f"Błąd parsowania pliku: {e}"})

            now_iso = datetime.now().isoformat(timespec="seconds")
            with db_lock:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("INSERT INTO scans (started_at, finished_at, status, mode, total_ips, scanned_ips) VALUES (?, ?, 'IMPORTED', 'import', ?, ?)",
                            (now_iso, now_iso, len(records), len(records)))
                sid = cur.lastrowid
                for r in records:
                    ip_s = str(r.get("ip", "")).strip()
                    if not ip_s:
                        continue
                    cur.execute("""
                        INSERT INTO findings (
                            scan_id, ip_enc, ip_hash, hostname_enc, port, protocol, service,
                            http_status, http_title_enc, headers_enc, cookies_enc, tls_info_enc,
                            redirect_enc, technologies, environment_tag, matched_signatures, confidence, analyst_notes_enc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sid, AtRestCipher.encrypt(ip_s), ip_digest(ip_s),
                        AtRestCipher.encrypt(str(r.get("hostname", ""))),
                        int(r.get("port", 80)), str(r.get("protocol", "tcp")), str(r.get("service", "http")),
                        int(r.get("http_status", 0) or 0),
                        AtRestCipher.encrypt(str(r.get("http_title", ""))),
                        AtRestCipher.encrypt(str(r.get("headers", ""))),
                        AtRestCipher.encrypt(str(r.get("cookies", ""))),
                        AtRestCipher.encrypt(str(r.get("tls_info", ""))),
                        AtRestCipher.encrypt(str(r.get("redirect", ""))),
                        str(r.get("technologies", "")),
                        str(r.get("environment_tag", "PROD/STANDARD")),
                        str(r.get("matched_signatures", "")),
                        int(r.get("confidence", 85) or 85),
                        AtRestCipher.encrypt(str(r.get("analyst_notes", "")))
                    ))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True, "message": f"Zaimportowano {len(records)} rekordów jako Skan #{sid}."})

        if path == "/api/targets":
            if not self._require_perm("add_delete"):
                return
            t_val = data.get("target", "").strip()
            if not t_val:
                return self._send_json({"ok": False, "error": "Podaj adres IP, CIDR lub domenę."})
            now_iso = datetime.now().isoformat(timespec="seconds")
            with db_lock:
                conn = get_db()
                conn.execute("INSERT INTO targets (target_enc, label, tags, created_at) VALUES (?, ?, ?, ?)",
                             (AtRestCipher.encrypt(t_val), data.get("label", ""), data.get("tags", ""), now_iso))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/targets/delete":
            if not self._require_perm("add_delete"):
                return
            with db_lock:
                conn = get_db()
                conn.execute("DELETE FROM targets WHERE id = ?", (int(data.get("id", 0)),))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/targets/import":
            if not self._require_perm("add_delete"):
                return
            fname = data.get("filename", "")
            content = data.get("content", "")
            rows = []
            try:
                if fname.lower().endswith(".json"):
                    raw = json.loads(content)
                    for item in raw:
                        if isinstance(item, str):
                            rows.append((item, "Import JSON", ""))
                        elif isinstance(item, dict):
                            rows.append((item.get("target", ""), item.get("label", ""), item.get("tags", "")))
                else:
                    for r in csv.DictReader(io.StringIO(content)):
                        rows.append((r.get("target", ""), r.get("label", ""), r.get("tags", "")))
            except Exception as e:
                return self._send_json({"ok": False, "error": f"Błąd importu: {e}"})

            now_iso = datetime.now().isoformat(timespec="seconds")
            added = 0
            with db_lock:
                conn = get_db()
                for t_val, lbl, tgs in rows:
                    if t_val and t_val.strip():
                        conn.execute("INSERT INTO targets (target_enc, label, tags, created_at) VALUES (?, ?, ?, ?)",
                                     (AtRestCipher.encrypt(t_val.strip()), lbl, tgs, now_iso))
                        added += 1
                conn.commit()
                conn.close()
            return self._send_json({"ok": True, "message": f"Zaimportowano {added} celów."})

        if path == "/api/signatures":
            if not self._require_perm("add_delete"):
                return
            try:
                re.compile(data.get("pattern", ""))
            except re.error as e:
                return self._send_json({"ok": False, "error": f"Błędne wyrażenie regularne: {e}"})
            with db_lock:
                conn = get_db()
                conn.execute("INSERT INTO signatures (name, category, match_type, pattern, severity) VALUES (?, ?, ?, ?, ?)", (
                    data.get("name", "Custom Sig"), data.get("category", "Konfiguracja"),
                    data.get("match_type", "header"), data.get("pattern", ""), data.get("severity", "INFO")
                ))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/signatures/delete":
            if not self._require_perm("add_delete"):
                return
            with db_lock:
                conn = get_db()
                conn.execute("DELETE FROM signatures WHERE id = ?", (int(data.get("id", 0)),))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/schedule":
            if not self._require_perm("modify"):
                return
            with db_lock:
                conn = get_db()
                conn.execute("""
                    UPDATE schedules SET interval_minutes = ?, window_start = ?, window_end = ?,
                    mode = ?, rate_limit = ?, enabled = ?
                """, (
                    int(data.get("interval_minutes", 120)),
                    data.get("window_start", "00:00"),
                    data.get("window_end", "23:59"),
                    data.get("mode", "balanced"),
                    int(data.get("rate_limit", 150)),
                    int(data.get("enabled", 0))
                ))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        if path == "/api/defectdojo":
            if not self._require_perm("modify"):
                return
            sid = int(data.get("scan_id", 0))
            items = get_decrypted_findings(sid)
            ok, msg = push_to_defectdojo(data.get("url", ""), data.get("token", ""), data.get("engagement_id", 1), items)
            return self._send_json({"ok": ok, "message": msg, "error": None if ok else msg})

        if path == "/api/users":
            if not self._require_perm("admin"):
                return
            uname = data.get("username", "").strip()
            pwd = data.get("password", "")
            role = data.get("role", "Odczyt")
            if not uname or not pwd or role not in ROLES:
                return self._send_json({"ok": False, "error": "Nieprawidłowe dane użytkownika."})
            salt = secrets.token_hex(16)
            ph = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 100_000).hex()
            try:
                with db_lock:
                    conn = get_db()
                    conn.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)", (uname, ph, salt, role))
                    conn.commit()
                    conn.close()
                return self._send_json({"ok": True})
            except sqlite3.IntegrityError:
                return self._send_json({"ok": False, "error": "Użytkownik już istnieje."})

        if path == "/api/users/delete":
            if not self._require_perm("admin"):
                return
            uid = int(data.get("id", 0))
            with db_lock:
                conn = get_db()
                conn.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (uid,))
                conn.commit()
                conn.close()
            return self._send_json({"ok": True})

        self._send_json({"error": "Not found"}, 404)


# ==============================================================================
# URUCHAMIANIE NATYWNEGO OKNA DESKTOPOWEGO (BEZ PRZEGLĄDARKI!)
# ==============================================================================

def launch_standalone_desktop_window(app_url: str):
    """
    Uruchamia Proculusa jako samodzielną aplikację okienkową (native OS window)
    bez otwierania okna przeglądarki, paska adresu czy zakładek.
    """
    # 1. Główny silnik natywnego okna: pywebview (Windows WebView2 / Cocoa / GTK)
    try:
        import webview
        window = webview.create_window(
            title="Proculus — Attack Surface Intelligence",
            url=app_url,
            width=1460,
            height=920,
            min_size=(1120, 740),
            background_color="#f4f7fb",
            text_select=True
        )
        try:
            if os.path.exists(ICON_PNG_PATH):
                webview.start(icon=ICON_PNG_PATH)
            else:
                webview.start()
        except TypeError:
            webview.start()
        return
    except ImportError:
        pass

    # 2. Fallback na Windows bez zainstalowanego pywebview: natywne okno Edge/Chrome w trybie --app (bez paska URL i zakładek)
    if os.name == "nt":
        candidates = [
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
        ]
        profile_dir = os.path.join(APP_DIR, ".proculus_runtime_profile")
        for exe in candidates:
            if exe and os.path.exists(exe):
                proc = subprocess.Popen([
                    exe,
                    f"--app={app_url}",
                    "--window-size=1460,920",
                    f"--user-data-dir={profile_dir}",
                    "--no-first-run",
                    "--no-default-browser-check"
                ])
                proc.wait()
                return

    # 3. Fallback uniwersalny Tkinter (natywne okno desktopowe z instrukcją instalacji pywebview)
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title("Proculus — Attack Surface Intelligence")
        root.geometry("620x320")
        root.configure(bg="#f4f7fb")
        if os.path.exists(ICON_ICO_PATH):
            try:
                root.iconbitmap(ICON_ICO_PATH)
            except Exception:
                pass
        tk.Label(root, text="PROCULUS", font=("Segoe UI", 22, "bold"), fg="#0077e6", bg="#f4f7fb").pack(pady=(24, 4))
        tk.Label(root, text="Silnik skanujący działa lokalnie w tle.", font=("Segoe UI", 11), fg="#0f172a", bg="#f4f7fb").pack()
        tk.Label(
            root,
            text="Aby uruchomić pełne natywne okno desktopowe lub zbudować plik .EXE,\nzainstaluj pakiet pywebview poleceniem:\n\npip install pywebview pyinstaller",
            font=("Consolas", 10), fg="#334155", bg="#ffffff", relief="solid", bd=1, padx=16, pady=12
        ).pack(pady=16)
        tk.Button(root, text="Zamknij aplikację", command=root.destroy, bg="#0077e6", fg="white", font=("Segoe UI", 10, "bold"), padx=16, pady=6).pack()
        root.mainloop()
    except Exception:
        while True:
            time.sleep(1)


def main():
    init_db()
    port = find_free_port(8765)
    threading.Thread(target=scheduler_loop, daemon=True).start()

    server = ThreadingHTTPServer((HOST_BIND, port), RequestHandler)
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    app_url = f"http://{HOST_BIND}:{port}"
    try:
        launch_standalone_desktop_window(app_url)
    finally:
        server.shutdown()
        server.server_close()
        os._exit(0)


if __name__ == "__main__":
    main()
Analizuję