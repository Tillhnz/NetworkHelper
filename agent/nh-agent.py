#!/usr/bin/env python3
"""NetworkHelper-Agent.

Läuft als systemd-Dienst auf einem Server (zum Beispiel dem LXC mit dem Nginx Proxy Manager) und
- liest die Zugriffsprotokolle des Proxy Managers mit und schickt neue Zeilen an NetworkHelper,
- meldet alle 30 Sekunden die offenen und verbundenen Netzwerkverbindungen (ss) und ein paar Systemdaten,
- setzt auf Wunsch die Sperrliste von NetworkHelper im Proxy Manager um (deny-Regeln, danach nginx neu laden).

Nur Python-Standardbibliothek, läuft ab Python 3.7. Konfiguration: /etc/networkhelper-agent.json
"""
import glob
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"
CONFIG = os.environ.get("NH_AGENT_CONFIG", "/etc/networkhelper-agent.json")
STATE_DIR = os.environ.get("NH_AGENT_STATE", "/var/lib/networkhelper-agent")
DEFAULTS = {
    "server": "",
    "token": "",
    "log_globs": [],
    "enforce_blocks": False,
    "npm_data_dir": "",       # Ordner, der im Proxy Manager als /data eingebunden ist
    "npm_container": "",      # Name des Docker-Containers, leer = Proxy Manager läuft ohne Docker
    "reload_cmd": "",         # eigener Befehl zum Neuladen, leer = automatisch
    "insecure": False,        # selbst signiertes Zertifikat bei NetworkHelper akzeptieren
    "interval": 30,
    "backfill_bytes": 262144,  # beim ersten Start so viel vom Ende jeder Datei nachliefern
}
BLOCK_FILE = "networkhelper_blocklist.conf"
INCLUDE_LINE = "include /data/nginx/custom/%s; # NetworkHelper-Sperrliste" % BLOCK_FILE
MAX_BATCH = 2000
MAX_READ = 2 * 1024 * 1024


def log(msg):
    sys.stdout.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    sys.stdout.flush()


def load_config():
    cfg = dict(DEFAULTS)
    with open(CONFIG, encoding="utf-8") as f:
        cfg.update(json.load(f))
    cfg["server"] = cfg["server"].rstrip("/")
    if not cfg["server"] or not cfg["token"]:
        raise SystemExit("server und token fehlen in " + CONFIG)
    return cfg


class Api:
    def __init__(self, cfg):
        self.base = cfg["server"] + "/api/agent"
        self.headers = {"Authorization": "Bearer " + cfg["token"], "Content-Type": "application/json",
                        "User-Agent": "NetworkHelper-Agent/" + VERSION}
        self.ctx = None
        if cfg.get("insecure"):
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def post(self, path, payload, timeout=30):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=self.headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
            return json.loads(r.read() or b"{}")


# ---------- Protokolldateien mitlesen ----------

class Tailer:
    def __init__(self, globs, backfill):
        self.globs = globs
        self.backfill = backfill
        self.path = os.path.join(STATE_DIR, "offsets.json")
        self.offsets = {}
        self.pending = {}  # Datei -> neue Position, wird erst nach erfolgreichem Senden übernommen
        try:
            with open(self.path, encoding="utf-8") as f:
                self.offsets = json.load(f)
        except (OSError, ValueError):
            self.offsets = {}

    def files(self):
        out = []
        for g in self.globs:
            out.extend(p for p in glob.glob(g) if os.path.isfile(p))
        return sorted(set(out))

    def read_new(self):
        """Liest neue, vollständige Zeilen aus allen Dateien (zusammen höchstens MAX_BATCH)."""
        lines = []
        self.pending = {}
        for p in self.files():
            room = MAX_BATCH - len(lines)
            if room <= 0:
                break
            try:
                st = os.stat(p)
            except OSError:
                continue
            known = self.offsets.get(p)
            first = known is None
            if first:
                start = max(0, st.st_size - self.backfill)
            elif known.get("inode") != st.st_ino or st.st_size < known.get("offset", 0):
                start = 0  # Datei wurde rotiert oder geleert
            else:
                start = known["offset"]
            if start >= st.st_size:
                if first:
                    self.pending[p] = {"inode": st.st_ino, "offset": st.st_size}
                continue
            try:
                with open(p, "rb") as f:
                    f.seek(start)
                    chunk = f.read(MAX_READ)
            except OSError:
                continue
            skip = 0
            if first and start > 0:  # beim Nachliefern mit einer ganzen Zeile beginnen
                nl = chunk.find(b"\n")
                skip = nl + 1 if nl >= 0 else len(chunk)
            data = chunk[skip:]
            end = data.rfind(b"\n")
            if end < 0:
                if first:
                    self.pending[p] = {"inode": st.st_ino, "offset": start + skip}
                continue
            raw = data[: end + 1].split(b"\n")[:-1][:room]
            lines.extend(b.decode("utf-8", "replace") for b in raw)
            consumed = sum(len(b) + 1 for b in raw)
            self.pending[p] = {"inode": st.st_ino, "offset": start + skip + consumed}
        return lines

    def commit(self):
        self.offsets.update(self.pending)
        current = set(self.files())
        self.offsets = {k: v for k, v in self.offsets.items() if k in current}
        self.pending = {}
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.offsets, f)
        os.replace(tmp, self.path)

    def describe(self):
        out = []
        for p in self.files()[:200]:
            try:
                size = os.path.getsize(p)
            except OSError:
                size = None
            off = self.offsets.get(p, {}).get("offset")
            out.append({"path": p, "size": size, "offset": off})
        return out


# ---------- Verbindungen und Systemdaten ----------

ADDR_RE = re.compile(r"^\[?(?P<addr>.*?)\]?(?:%\S+)?:(?P<port>\*|\d+)$")
PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def split_addr(text):
    m = ADDR_RE.match(text)
    if not m:
        return text, None
    addr = m.group("addr")
    if addr.startswith("::ffff:"):
        addr = addr[7:]
    port = m.group("port")
    return addr, (int(port) if port.isdigit() else None)


def connections():
    """Aufgebaute TCP-Verbindungen und lauschende Sockets über ss (iproute2)."""
    est, listen = [], []
    if not shutil.which("ss"):
        return est, listen
    try:
        out = subprocess.run(["ss", "-Htunap"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return est, listen
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, state_, local, peer = parts[0], parts[1], parts[4], parts[5]
        proc = PROC_RE.search(line)
        pname = proc.group(1) if proc else None
        laddr, lport = split_addr(local)
        raddr, rport = split_addr(peer)
        if proto == "tcp" and state_ == "ESTAB":
            if raddr in ("127.0.0.1", "::1"):
                continue
            est.append({"proto": "tcp", "local": laddr, "lport": lport, "remote": raddr, "rport": rport, "process": pname})
        elif (proto == "tcp" and state_ == "LISTEN") or (proto == "udp" and state_ == "UNCONN" and rport is None):
            if laddr in ("127.0.0.1", "::1") or laddr.startswith("127."):
                continue
            listen.append({"proto": proto, "addr": laddr, "port": lport, "process": pname})
    # Doppelte (IPv4/IPv6) zusammenfassen
    seen, uniq = set(), []
    for item in listen:
        key = (item["proto"], item["port"], item["process"])
        if key not in seen:
            seen.add(key)
            uniq.append(item)
    return est[:5000], uniq[:2000]


def read_first(path, default=""):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return default


def system_info():
    info = {"os": "", "kernel": platform.release(), "python": platform.python_version()}
    for line in read_first("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            info["os"] = line.split("=", 1)[1].strip('"')
    try:
        info["uptime_s"] = int(float(read_first("/proc/uptime", "0").split()[0]))
        info["load"] = [round(x, 2) for x in os.getloadavg()]
    except (ValueError, OSError, IndexError):
        pass
    mem = {}
    for line in read_first("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            mem[k] = int(v.split()[0]) * 1024
    if mem:
        info["mem_total"], info["mem_available"] = mem.get("MemTotal"), mem.get("MemAvailable")
    addrs = []
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 4:
                    addrs.append(p[3].split("/")[0])
        except (OSError, subprocess.SubprocessError):
            pass
    info["addrs"] = addrs[:20]
    env1 = read_first("/proc/1/environ").replace("\0", " ")
    info["container"] = "lxc" if "container=lxc" in env1 else ("docker" if os.path.exists("/.dockerenv") else None)
    if shutil.which("docker"):
        try:
            out = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], capture_output=True, text=True, timeout=8).stdout
            info["docker"] = [dict(zip(("name", "ports"), l.split("\t", 1))) for l in out.splitlines()][:100]
        except (OSError, subprocess.SubprocessError):
            pass
    return info


# ---------- Sperrliste im Proxy Manager ----------

class Blocker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.applied = None
        self.status = "aus" if not cfg.get("enforce_blocks") else "noch nicht angewendet"
        self.custom = os.path.join(cfg.get("npm_data_dir") or "/data", "nginx", "custom")

    def _nginx(self, *args):
        c = self.cfg.get("npm_container")
        if c:
            return ["docker", "exec", c, "nginx"] + list(args)
        for binary in ("nginx", "/usr/local/openresty/nginx/sbin/nginx", "openresty"):
            if shutil.which(binary) or os.path.exists(binary):
                return [binary] + list(args)
        return ["nginx"] + list(args)

    def _run(self, cmd):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=isinstance(cmd, str))
        return p.returncode, (p.stdout + p.stderr).strip()[-300:]

    def apply(self, entries, digest):
        if not self.cfg.get("enforce_blocks"):
            return
        if digest == self.applied:
            return
        target = os.path.join(self.custom, BLOCK_FILE)
        include = os.path.join(self.custom, "server_proxy.conf")
        try:
            os.makedirs(self.custom, exist_ok=True)
            old = read_first(target, None)
            body = "# Von NetworkHelper verwaltet, wird überschrieben. Stand: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S")
            body += "".join("deny %s;\n" % e for e in entries if re.fullmatch(r"[0-9a-fA-F:./]+", e))
            with open(target + ".tmp", "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(target + ".tmp", target)
            inc = read_first(include, "")
            if INCLUDE_LINE not in inc:
                with open(include, "a", encoding="utf-8") as f:
                    f.write(("\n" if inc and not inc.endswith("\n") else "") + INCLUDE_LINE + "\n")
            code, out = self._run(self._nginx("-t"))
            if code != 0:
                if old is None:
                    os.remove(target)
                else:
                    with open(target, "w", encoding="utf-8") as f:
                        f.write(old)
                self.status = "Fehler in der nginx-Konfiguration, Sperrliste zurückgenommen: " + out[-200:]
                log(self.status)
                return
            reload_cmd = self.cfg.get("reload_cmd") or self._nginx("-s", "reload")
            code, out = self._run(reload_cmd)
            if code != 0:
                self.status = "nginx ließ sich nicht neu laden: " + out[-200:]
                log(self.status)
                return
            self.applied = digest
            self.status = "%d Einträge aktiv" % len(entries)
            log("Sperrliste angewendet: " + self.status)
        except Exception as e:  # noqa: BLE001
            self.status = "Fehler: %s" % e
            log(self.status)


# ---------- Hauptschleife ----------

def main():
    cfg = load_config()
    api = Api(cfg)
    tailer = Tailer(cfg.get("log_globs") or [], int(cfg.get("backfill_bytes") or 0))
    blocker = Blocker(cfg)
    interval = max(10, int(cfg.get("interval") or 30))
    log("NetworkHelper-Agent %s startet, Server %s, %d Protokolldateien" % (VERSION, cfg["server"], len(tailer.files())))
    next_state = 0.0
    backoff = 2
    while True:
        try:
            lines = tailer.read_new()
            if lines:
                api.post("/logs", {"lines": lines}, timeout=60)
                tailer.commit()
            elif tailer.pending:
                tailer.commit()
            if time.time() >= next_state:
                est, listen = connections()
                res = api.post("/state", {
                    "hostname": socket.gethostname(), "version": VERSION, "info": system_info(),
                    "established": est, "listening": listen, "log_files": tailer.describe(),
                    "enforce_blocks": bool(cfg.get("enforce_blocks")), "block_status": blocker.status[:300],
                })
                blocker.apply(res.get("blocklist", []), res.get("blocklist_hash"))
                interval = max(10, int(res.get("interval") or interval))
                next_state = time.time() + interval
            backoff = 2
            time.sleep(1 if len(lines) >= MAX_BATCH else 3)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log("NetworkHelper lehnt den Token ab (401). Wurde der Agent gelöscht oder der Token erneuert? Warte 5 Minuten.")
                time.sleep(300)
                continue
            log("Fehler %s vom Server, neuer Versuch in %d s" % (e.code, backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log("Server nicht erreichbar (%s), neuer Versuch in %d s" % (getattr(e, "reason", e), backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        c = load_config()
        t = Tailer(c.get("log_globs") or [], 0)
        print(json.dumps({"files": t.files(), "connections": connections()[0][:5], "info": system_info()}, indent=2))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(VERSION)
        sys.exit(0)
    main()
