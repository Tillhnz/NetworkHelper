#!/usr/bin/env python3
"""NetworkHelper-Agent.

Läuft als systemd-Dienst auf einem Server (zum Beispiel dem LXC mit dem Nginx Proxy Manager) und
- liest die Zugriffsprotokolle des Proxy Managers mit und schickt neue Zeilen an NetworkHelper,
- meldet alle 30 Sekunden die offenen und verbundenen Netzwerkverbindungen (ss) und ein paar Systemdaten,
- setzt auf Wunsch die Sperrliste von NetworkHelper im Proxy Manager um (deny-Regeln, Länder- und Listen-Sperren,
  danach nginx neu laden),
- passt auf den Server selbst auf: erfolgreiche und fehlgeschlagene SSH-Anmeldungen, Benutzerkonten mit Login,
  Prüfsummen wichtiger Systemdateien (authorized_keys, sudoers, cron, systemd …). Inhalte verlassen den Server nicht,
  nur Prüfsummen und Namen,
- aktualisiert sich selbst, wenn NetworkHelper eine neuere Version anbietet,
- richtet auf Wunsch fail2ban ein (--setup-fail2ban), meldet dessen Sperren und setzt die Sperrliste von
  NetworkHelper zusätzlich in der Firewall um.

Nur Python-Standardbibliothek, läuft ab Python 3.7. Konfiguration: /etc/networkhelper-agent.json
"""
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

VERSION = "1.4.0"
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
    "watch": True,            # Anmeldungen, Benutzer und wichtige Dateien beobachten
    "watch_interval": 300,
    "auto_update": True,      # neuere Agent-Version von NetworkHelper übernehmen
    "inventory": True,        # installierte Pakete melden (für den Lückenwächter)
    "allow_updates": False,   # Updates auf Anweisung von NetworkHelper (nur fest eingebaute Aktionen)
    "inventory_hours": 24,
    "syft": "",               # Pfad zu syft, leer = automatisch suchen
}
BLOCK_FILE = "networkhelper_blocklist.conf"
INCLUDE_LINE = "include /data/nginx/custom/%s; # NetworkHelper-Sperrliste" % BLOCK_FILE
HTTP_FILE = "networkhelper_http.conf"
HTTP_INCLUDE_LINE = "include /data/nginx/custom/%s; # NetworkHelper: Länder- und Listen-Sperren" % HTTP_FILE
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

    def get_text(self, url, timeout=60):
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
            return r.read().decode("utf-8")


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


# ---------- Inventur: was ist installiert? (für den Lückenwächter) ----------

SYFT_VERSION = "1.55.0"
SYFT_SHA = {"amd64": "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
            "arm64": "929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304"}
SYFT_PATHS = ["/usr/local/lib/networkhelper-agent/syft", "/usr/local/bin/syft", "/usr/bin/syft"]
HOST_DIRS = ["/usr/local", "/opt", "/srv", "/root", "/home"]
NICE = ["nice", "-n", "19"] + (["ionice", "-c", "3"] if shutil.which("ionice") else [])


def os_release(root=""):
    data = {}
    try:
        with open(root + "/etc/os-release", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                data[k] = v.strip('"')
    except OSError:
        pass
    return "%s:%s" % (data.get("ID", ""), data.get("VERSION_ID", "")) if data.get("ID") else ""


def syft_rows(doc):
    """Wandelt die Syft-Ausgabe in kompakte Zeilen [typ, name, version, purl] (Systempakete: Quellpaket)."""
    rows, seen = [], set()
    for a in doc.get("artifacts") or []:
        typ, name, version = a.get("type", ""), a.get("name", ""), a.get("version", "")
        meta = a.get("metadata") or {}
        if typ == "deb" and meta.get("source"):
            name, version = meta["source"], meta.get("sourceVersion") or version
        elif typ == "apk" and meta.get("originPackage"):
            name = meta["originPackage"]
        if not name or not version:
            continue
        purl = a.get("purl", "") if typ == "java-archive" else ""
        key = (typ, name, version)
        if key in seen:
            continue
        seen.add(key)
        rows.append([typ, name, version, purl] if purl else [typ, name, version])
    d = doc.get("distro") or {}
    distro = "%s:%s" % (d.get("id"), d.get("versionID")) if d.get("id") and d.get("versionID") else ""
    return rows, distro


def run_syft(syft, source, extra=()):
    out = subprocess.run(NICE + [syft, source, "-o", "json", "-q"] + list(extra), capture_output=True, text=True, timeout=900)
    if out.returncode != 0:
        raise RuntimeError((out.stderr or "syft fehlgeschlagen").strip().splitlines()[-1][:200])
    return syft_rows(json.loads(out.stdout or "{}"))


def system_packages():
    """Ohne Syft: Paketliste des Systems (dpkg oder apk)."""
    rows = []
    if shutil.which("dpkg-query"):
        out = subprocess.run(["dpkg-query", "-W", "-f", "${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"],
                             capture_output=True, text=True, timeout=60).stdout
        seen = set()
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) >= 3 and p[2].startswith("ii") and (p[0], p[1]) not in seen:
                seen.add((p[0], p[1]))
                rows.append(["deb", p[0], p[1]])
    elif shutil.which("apk"):
        out = subprocess.run(["apk", "list", "-I"], capture_output=True, text=True, timeout=60).stdout
        seen = set()
        for line in out.splitlines():
            m = re.match(r"^(\S+)-(\d\S*-r\d+) \S+ \{([^}]+)\}", line)
            if m and (m.group(3), m.group(2)) not in seen:
                seen.add((m.group(3), m.group(2)))
                rows.append(["apk", m.group(3), m.group(2)])
    return rows


def running_containers():
    """{image_id: {"image": name, "containers": [{name, ports}]}} der laufenden Docker-Container."""
    if not shutil.which("docker"):
        return {}
    try:
        ps = subprocess.run(["docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"],
                            capture_output=True, text=True, timeout=20).stdout
        rows = [l.split("\t") for l in ps.splitlines() if l.strip()]
        if not rows:
            return {}
        fmt = ("{{.Id}}\t{{.Image}}\t{{.Config.Image}}\t{{index .Config.Labels \"com.docker.compose.project\"}}\t"
               "{{index .Config.Labels \"com.docker.compose.service\"}}\t{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}\t"
               "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}")
        ins = subprocess.run(["docker", "inspect", "--format", fmt] + [r[0] for r in rows],
                             capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    meta = {}
    for line in ins.splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            meta[p[0]] = p[1:] + [""] * (7 - len(p))
    out = {}
    for r in rows:
        if r[0] not in meta:
            continue
        image_id, image, project, service, wdir, files = meta[r[0]][:6]
        e = out.setdefault(image_id, {"image": image, "containers": []})
        c = {"name": r[1], "ports": r[2] if len(r) > 2 else ""}
        if project and service:
            c["compose"] = {"project": project, "service": service, "dir": wdir, "files": files}
        e["containers"].append(c)
    return out


def install_syft():
    """Lädt Syft (feste Version, Prüfsumme fest eingetragen), falls es fehlt. Gibt den Pfad zurück oder None."""
    import io
    import tarfile
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not arch:
        return None
    url = "https://github.com/anchore/syft/releases/download/v%s/syft_%s_linux_%s.tar.gz" % (SYFT_VERSION, SYFT_VERSION, arch)
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != SYFT_SHA[arch]:
        raise RuntimeError("Prüfsumme von Syft stimmt nicht")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = tar.getmember("syft")
        binary = tar.extractfile(member).read()
    path = SYFT_PATHS[0]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".new", "wb") as f:
        f.write(binary)
    os.chmod(path + ".new", 0o755)
    os.replace(path + ".new", path)
    log("Syft %s installiert (für die Inventur)" % SYFT_VERSION)
    return path


class Inventory(threading.Thread):
    """Läuft im Hintergrund: einmal am Tag und sobald ein Container mit neuem Image startet."""

    def __init__(self, cfg, api):
        super().__init__(daemon=True, name="inventur")
        self.cfg, self.api = cfg, api
        self.syft = cfg.get("syft") or next((p for p in SYFT_PATHS if os.access(p, os.X_OK)), None) or shutil.which("syft")
        self.cache = {}  # image_id -> (zeit, zeilen, distro, fehler)
        self.last_full = 0.0
        self.last_sig = None
        self.force = threading.Event()

    def scan_image(self, image_id):
        hit = self.cache.get(image_id)
        if hit and time.time() - hit[0] < float(self.cfg.get("inventory_hours") or 24) * 3600:
            return hit[1:]
        try:
            rows, distro = run_syft(self.syft, "docker:" + image_id)
            res = (rows, distro, None)
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as e:
            res = (None, "", str(e)[:200])
        self.cache[image_id] = (time.time(),) + res
        return res

    def scan_host(self):
        rows = system_packages()
        err = None
        if self.syft:
            seen = {tuple(r[:3]) for r in rows}
            for d in HOST_DIRS:
                if not os.path.isdir(d):
                    continue
                try:
                    extra, _ = run_syft(self.syft, "dir:" + d, ["--override-default-catalogers", "image",
                                                                "--exclude", "./**/.cache/**", "--exclude", "./**/docker/**"])
                except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as e:
                    err = "%s: %s" % (d, e)
                    continue
                for r in extra:
                    if r[0] not in ("deb", "apk", "rpm") and tuple(r[:3]) not in seen:
                        seen.add(tuple(r[:3]))
                        rows.append(r)
        return rows, err

    def collect(self):
        targets = []
        rows, err = self.scan_host()
        targets.append({"key": "host", "distro": os_release(), "packages": rows, "error": err,
                        "scanner": ("syft " if self.syft else "") + ("dpkg" if shutil.which("dpkg-query") else "apk")})
        for image_id, info in running_containers().items():
            t = {"key": "image:" + image_id.replace("sha256:", "")[:64], "image": info["image"], "containers": info["containers"]}
            if self.syft:
                rows, distro, err = self.scan_image(image_id)
                t.update({"packages": rows, "distro": distro, "error": err, "scanner": "syft"})
            else:
                t.update({"packages": None, "error": "syft fehlt: Agent mit --inventory neu installieren"})
            targets.append(t)
        return targets

    def signature(self):
        return sorted(running_containers())

    def run(self):
        time.sleep(90)
        if not self.syft:
            try:
                self.syft = install_syft()
            except Exception as e:  # noqa: BLE001
                log("Syft ließ sich nicht installieren (%s), melde nur Systempakete" % e)
        while True:
            try:
                sig = self.signature()
                due = time.time() - self.last_full > float(self.cfg.get("inventory_hours") or 24) * 3600
                if due or sig != self.last_sig or self.force.is_set():
                    self.force.clear()
                    targets = self.collect()
                    self.api.post("/inventory", {"targets": targets, "complete": True, "syft": bool(self.syft)}, timeout=180)
                    self.last_full, self.last_sig = time.time(), sig
                    log("Inventur gemeldet: %d Ziele, %d Pakete" % (len(targets), sum(len(t.get("packages") or []) for t in targets)))
            except Exception as e:  # noqa: BLE001 - die Inventur darf den Agenten nie stoppen
                log("Inventur fehlgeschlagen: %s" % e)
            self.force.wait(600)


# ---------- Updates auf Anweisung (nur fest eingebaute Aktionen) ----------

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")


def sh(cmd, timeout=900, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, ((p.stdout or "") + (p.stderr or ""))[-3000:]


def container_info(name):
    rc, out = sh(["docker", "inspect", "--format",
                  "{{.Image}}\t{{.Config.Image}}\t{{index .Config.Labels \"com.docker.compose.project\"}}\t"
                  "{{index .Config.Labels \"com.docker.compose.service\"}}\t{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}\t"
                  "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}", name], 30)
    if rc != 0:
        raise RuntimeError("Container %s nicht gefunden" % name)
    p = out.strip().split("\t")
    return dict(zip(["image_id", "image", "project", "service", "dir", "files"], p + [""] * (6 - len(p))))


def wait_healthy(name, seconds=90):
    end = time.time() + seconds
    state = ""
    while time.time() < end:
        rc, out = sh(["docker", "inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name], 30)
        state = out.strip()
        if rc == 0 and state.startswith("running") and "starting" not in state:
            # noch kurz beobachten, ob er gleich wieder abstürzt
            time.sleep(15)
            rc, out = sh(["docker", "inspect", "--format", "{{.State.Status}} {{.State.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name], 30)
            parts = out.split()
            if rc == 0 and parts and parts[0] == "running" and "unhealthy" not in parts:
                return True, out.strip()
            return False, out.strip()
        time.sleep(5)
    return False, state


def update_container(name):
    """Neueres Image holen und den Container über Docker Compose neu erstellen. Klappt der Start nicht: zurück."""
    if not NAME_RE.match(name):
        raise RuntimeError("ungültiger Containername")
    info = container_info(name)
    if not (info["project"] and info["service"]):
        return "manual", "Der Container wurde nicht mit Docker Compose gestartet. Bitte von Hand aktualisieren."
    if sh(["docker", "compose", "version"], 30)[0] == 0:
        compose = ["docker", "compose", "-p", info["project"]]
    elif shutil.which("docker-compose"):
        compose = ["docker-compose", "-p", info["project"]]
    else:
        return "manual", "Docker Compose ist nicht installiert."
    for f in (info["files"] or "").split(","):
        if f and os.path.isfile(f):
            compose += ["-f", f]
    cwd_ok = info["dir"] and os.path.isdir(info["dir"])
    env = dict(os.environ)
    run = lambda args, t=900: subprocess.run(compose + args, capture_output=True, text=True, timeout=t, env=env,  # noqa: E731
                                             cwd=info["dir"] if cwd_ok else None)
    p = run(["pull", info["service"]])
    logtxt = (p.stdout + p.stderr)[-1500:]
    if p.returncode != 0:
        return "failed", "docker compose pull fehlgeschlagen:\n" + logtxt
    rc, new_id = sh(["docker", "image", "inspect", "--format", "{{.Id}}", info["image"]], 30)
    if rc == 0 and new_id.strip() == info["image_id"]:
        return "no_update", ("Es gibt kein neueres Image für %s. Entweder hat der Hersteller die Lücke noch nicht behoben, "
                             "oder im Compose-File steht eine feste Version (dann dort eine neuere eintragen)." % info["image"])
    p = run(["up", "-d", "--no-deps", info["service"]])
    logtxt += "\n" + (p.stdout + p.stderr)[-1500:]
    ok, state = (False, "up fehlgeschlagen") if p.returncode != 0 else wait_healthy(name)
    if ok:
        return "ok", "Aktualisiert auf %s.\n%s" % (new_id.strip()[:19], logtxt[-800:])
    # zurück zum alten Image
    sh(["docker", "tag", info["image_id"], info["image"]], 30)
    p2 = run(["up", "-d", "--no-deps", info["service"]])
    return "rolled_back", ("Der neue Container startete nicht sauber (%s). Das alte Image läuft wieder.\n%s\n%s"
                           % (state, logtxt[-1000:], (p2.stdout + p2.stderr)[-500:]))


def update_host_packages(sources):
    """Systempakete aktualisieren, die zu den genannten Quellpaketen gehören (nur Upgrades, nichts Neues)."""
    sources = {s for s in sources if NAME_RE.match(s)}
    if not sources:
        return "failed", "keine Pakete angegeben"
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if shutil.which("apt-get"):
        rc, out = sh(["dpkg-query", "-W", "-f", "${binary:Package}\t${source:Package}\t${db:Status-Abbrev}\n"], 60)
        bins = sorted({l.split("\t")[0] for l in out.splitlines()
                       if l.count("\t") == 2 and l.split("\t")[1] in sources and l.split("\t")[2].startswith("ii")})
        if not bins:
            return "failed", "Keines der Pakete ist installiert."
        rc, out1 = sh(["apt-get", "update", "-q"], 300, env)
        rc, out2 = sh(["apt-get", "install", "-y", "-q", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold",
                       "-o", "Dpkg::Options::=--force-confdef"] + bins, 1800, env)
        status = "ok" if rc == 0 else "failed"
        restart = " Ein Neustart kann nötig sein (z. B. bei Kernel oder libc)." if os.path.exists("/var/run/reboot-required") else ""
        return status, "apt-get install --only-upgrade %s\n%s%s" % (" ".join(bins[:30]), out2[-1500:], restart)
    if shutil.which("apk"):
        rc, out = sh(["apk", "list", "-I"], 60)
        names = sorted({m.group(1) for m in (re.match(r"^(\S+)-\d\S*-r\d+ \S+ \{([^}]+)\}", l) for l in out.splitlines())
                        if m and m.group(2) in sources})
        rc, out2 = sh(["apk", "upgrade", "--update-cache"] + (names or sorted(sources)), 1800)
        return ("ok" if rc == 0 else "failed"), out2[-1500:]
    return "failed", "Unbekannter Paketmanager"


class Updater(threading.Thread):
    def __init__(self, api, inventory):
        super().__init__(daemon=True, name="updates")
        self.api, self.inventory = api, inventory
        self.queue, self.seen = [], set()
        self.lock = threading.Lock()
        self.wake = threading.Event()

    def add(self, actions):
        with self.lock:
            for a in actions or []:
                if isinstance(a, dict) and a.get("id") not in self.seen:
                    self.seen.add(a.get("id"))
                    self.queue.append(a)
        self.wake.set()

    def run(self):
        while True:
            self.wake.wait(60)
            self.wake.clear()
            while True:
                with self.lock:
                    a = self.queue.pop(0) if self.queue else None
                if a is None:
                    break
                self.api.post("/action-result", {"id": a["id"], "status": "running", "log": ""})
                try:
                    if a.get("kind") == "container_update":
                        status, text = update_container(str(a.get("container", "")))
                    elif a.get("kind") == "host_packages":
                        status, text = update_host_packages([str(x) for x in a.get("packages") or []][:200])
                    else:
                        status, text = "failed", "unbekannte Aktion"
                except Exception as e:  # noqa: BLE001
                    status, text = "failed", str(e)[:500]
                log("Aktion %s (%s): %s" % (a.get("id"), a.get("kind"), status))
                try:
                    self.api.post("/action-result", {"id": a["id"], "status": status, "log": text[-3000:]})
                except Exception as e:  # noqa: BLE001
                    log("Ergebnis nicht gemeldet: %s" % e)
                if self.inventory is not None:
                    self.inventory.cache.clear()
                    self.inventory.force.set()


# ---------- Wachsamkeit: Anmeldungen, Benutzer, wichtige Dateien ----------

WATCH_GLOBS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d/*",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*", "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys",
    "/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/etc/systemd/system/*.service",
    "/etc/rc.local", "/etc/ld.so.preload", "/etc/pve/priv/authorized_keys", "/etc/pam.d/sshd", "/etc/pam.d/common-auth",
]
ACCEPT_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")
FAIL_RE = re.compile(r"(?:Failed password for (?:invalid user )?(\S+)|Invalid user (\S+)) from (\S+)")
PVE_OK_RE = re.compile(r"successful auth for user '([^']+)'")
PVE_FAIL_RE = re.compile(r"authentication failure; rhost=(\S+) user=(\S+)")


def file_hashes():
    out = {}
    for g in WATCH_GLOBS:
        for p in sorted(glob.glob(g))[:100]:
            try:
                if not os.path.isfile(p) or os.path.getsize(p) > 5 * 1024 * 1024:
                    continue
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                out[p] = h.hexdigest()
            except OSError:
                continue
            if len(out) >= 400:
                return out
    return out


def login_users():
    """Konten, mit denen man sich anmelden kann (uid 0 oder ab 1000, mit Shell), dazu Mitglieder von sudo/wheel."""
    users, admins = [], set()
    for line in read_first("/etc/group").splitlines():
        p = line.split(":")
        if len(p) >= 4 and p[0] in ("sudo", "wheel", "admin") and p[3]:
            admins.update(x for x in p[3].split(",") if x)
    for line in read_first("/etc/passwd").splitlines():
        p = line.split(":")
        if len(p) < 7:
            continue
        try:
            uid = int(p[2])
        except ValueError:
            continue
        shell = p[6].strip()
        if (uid == 0 or uid >= 1000) and not shell.endswith(("nologin", "false", "sync")) and uid != 65534:
            users.append({"name": p[0], "uid": uid, "shell": shell, "admin": uid == 0 or p[0] in admins})
    return users[:200]


class AuthWatcher:
    """Liest neue Anmelde-Ereignisse aus dem Journal (oder /var/log/auth.log)."""

    def __init__(self):
        self.path = os.path.join(STATE_DIR, "auth_cursor.json")
        try:
            with open(self.path, encoding="utf-8") as f:
                self.cursor = json.load(f)
        except (OSError, ValueError):
            self.cursor = {}

    def _save(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(self.path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(self.cursor, f)
        os.replace(self.path + ".tmp", self.path)

    def _lines(self):
        since = self.cursor.get("since") or (time.time() - 3600)
        now = time.time()
        if shutil.which("journalctl"):
            try:
                cmd = ["journalctl", "--no-pager", "-o", "short-unix", "--since", "@%d" % int(since), "--until", "@%d" % int(now),
                       "SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "SYSLOG_IDENTIFIER=pvedaemon"]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
                self.cursor["since"] = now
                return out.splitlines()[-5000:]
            except (OSError, subprocess.SubprocessError):
                pass
        for path in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(path):
                st = os.stat(path)
                off = self.cursor.get("offset", 0) if self.cursor.get("inode") == st.st_ino else max(0, st.st_size - 65536)
                if off > st.st_size:
                    off = 0
                with open(path, "rb") as f:
                    f.seek(off)
                    data = f.read(MAX_READ)
                self.cursor.update({"inode": st.st_ino, "offset": off + len(data), "since": now})
                return data.decode("utf-8", "replace").splitlines()[-5000:]
        self.cursor["since"] = now
        return []

    def collect(self):
        logins, fails = [], {}
        for line in self._lines():
            ts = None
            m0 = re.match(r"^(\d+)(?:\.\d+)?\s", line)
            if m0:
                ts = int(m0.group(1))
            m = ACCEPT_RE.search(line)
            if m:
                logins.append({"ts": ts, "method": m.group(1), "user": m.group(2), "ip": m.group(3), "service": "ssh"})
                continue
            m = FAIL_RE.search(line)
            if m:
                ip = m.group(3)
                fails[ip] = fails.get(ip, 0) + 1
                continue
            m = PVE_OK_RE.search(line)
            if m:
                logins.append({"ts": ts, "method": "password", "user": m.group(1), "ip": None, "service": "proxmox"})
                continue
            m = PVE_FAIL_RE.search(line)
            if m:
                ip = m.group(1)
                fails[ip] = fails.get(ip, 0) + 1
        self._save()
        return logins[-500:], dict(sorted(fails.items(), key=lambda x: -x[1])[:200])


def watch_snapshot(auth):
    logins, fails = auth.collect()
    return {"logins": logins, "failures": fails, "users": login_users(), "files": file_hashes(),
            "proxmox": os.path.isdir("/etc/pve")}


# ---------- Selbst-Update ----------

def self_update(api, cfg, offered):
    if not cfg.get("auto_update", True) or not offered or offered == VERSION:
        return
    if tuple(int(x) for x in re.findall(r"\d+", offered)[:3]) <= tuple(int(x) for x in re.findall(r"\d+", VERSION)[:3]):
        return
    me = os.path.abspath(__file__)
    try:
        code = api.get_text(cfg["server"] + "/api/agent/files/nh-agent.py")
        tmp = me + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(code)
        import py_compile
        py_compile.compile(tmp, doraise=True)
        os.chmod(tmp, 0o755)
        os.replace(tmp, me)
        log("Agent auf Version %s aktualisiert, starte neu" % offered)
        sys.exit(0)  # systemd startet den Agenten mit der neuen Datei neu
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        log("Selbst-Update fehlgeschlagen: %s" % e)


# ---------- fail2ban ----------

F2B_DIR = os.environ.get("NH_F2B_DIR", "/etc/fail2ban")
F2B_JAIL_FILE = "jail.d/networkhelper.local"
F2B_SYNC_JAIL = "networkhelper"
F2B_MANUAL_LOG = "/var/log/networkhelper-fail2ban.log"
F2B_LAN = "127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"
F2B_IP_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")
F2B_JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")

# Proxy Manager: Zeilenanfang „[Zeit] … Status …“ und „[Client IP]“ (Formate der Version 2.x)
F2B_NPM_PREFIX = r'^ ?(?:- )?(?:\d{3} )?'  # der Zeitstempel ist hier schon abgeschnitten
F2B_FILTERS = {
    "networkhelper-npm-auth": {
        "about": "Viele abgelehnte Anmeldungen (401/403) an deinen Webseiten",
        "body": "[Definition]\n"
                "failregex = " + F2B_NPM_PREFIX + r'(?:401|403) (?:\S+ )?- ?\S+ \S+ \S+ "[^"]*" \[Client <HOST>\]' + "\n"
                "ignoreregex =\n"
                "datepattern = ^\\[%%d/%%b/%%Y:%%H:%%M:%%S %%z\\]\n",
    },
    "networkhelper-npm-scan": {
        "about": "Suche nach Schwachstellen (/.env, /.git, wp-login.php …), die ins Leere ging",
        "body": "[Definition]\n"
                "failregex = " + F2B_NPM_PREFIX + r'4\d\d (?:\S+ )?- ?\S+ \S+ \S+ "[^"]*?(?:/\.env|/\.git/|/\.aws/|/\.ssh/|wp-login\.php|xmlrpc\.php|/phpmyadmin|/vendor/phpunit|eval-stdin\.php|/cgi-bin/|/boaform|/HNAP1|/actuator|/\.DS_Store|/server-status)[^"]*" \[Client <HOST>\]' + "\n"
                "ignoreregex =\n"
                "datepattern = ^\\[%%d/%%b/%%Y:%%H:%%M:%%S %%z\\]\n",
    },
    "networkhelper-proxmox": {
        "about": "Falsche Passwörter an der Proxmox-Oberfläche",
        "body": "[Definition]\n"
                "failregex = authentication (?:verification )?failure; rhost=(?:::ffff:)?<HOST> user=\\S+ msg=.*$\n"
                "ignoreregex =\n"
                "journalmatch = _SYSTEMD_UNIT=pvedaemon.service\n",
    },
    "networkhelper": {
        "about": "Sperrliste von NetworkHelper (wird vom Agenten gepflegt)",
        "body": "[Definition]\nfailregex =\nignoreregex =\n",
    },
}


def f2b_detect(cfg):
    """Was gibt es auf diesem Server zu schützen?"""
    npm_dir = cfg.get("npm_data_dir") or ""
    return {
        "sshd": bool(shutil.which("sshd") or os.path.exists("/usr/sbin/sshd")),
        "journal": bool(shutil.which("journalctl")),
        "npm_logs": os.path.join(npm_dir, "logs") if npm_dir and os.path.isdir(os.path.join(npm_dir, "logs")) else "",
        "npm_docker": bool(cfg.get("npm_container")),
        "proxmox": os.path.isdir("/etc/pve"),
        "nft": bool(shutil.which("nft")),
    }


def f2b_jail_config(det, own_ips=()):
    """Inhalt von jail.d/networkhelper.local. Heimnetz und eigene IP werden nie gesperrt."""
    ignore = F2B_LAN + "".join(" " + ip for ip in own_ips if F2B_IP_RE.match(ip))
    if det["nft"]:
        multi, allports = "nftables-multiport", "nftables-allports"
    else:
        multi, allports = "iptables-multiport", "iptables-allports"
    # Läuft der Proxy Manager in Docker, gehen Besucher durch die FORWARD-Kette: dort (DOCKER-USER) sperren
    npm_action = "iptables-allports[name=%(__name__)s, chain=DOCKER-USER]" if det["npm_docker"] else allports
    out = ["# Von NetworkHelper verwaltet (nh-agent --setup-fail2ban). Eigene Anpassungen bitte in eine andere Datei.",
           "# Das Heimnetz und deine öffentliche IP stehen in ignoreip und werden nie gesperrt.", ""]

    def jail(name, lines):
        out.extend(["[%s]" % name, "enabled = true", "ignoreip = " + ignore, "bantime.increment = true",
                    "bantime.maxtime = 1w"] + lines + [""])

    if det["sshd"]:
        jail("sshd", ["mode = aggressive", "port = ssh", "maxretry = 5", "findtime = 10m", "bantime = 1h",
                      "banaction = " + multi] + (["backend = systemd"] if det["journal"] else []))
    if det["npm_logs"]:
        logs = os.path.join(det["npm_logs"], "proxy-host-*_access.log")
        jail("networkhelper-npm-auth", ["filter = networkhelper-npm-auth", "logpath = " + logs, "backend = auto",
                                        "maxretry = 15", "findtime = 5m", "bantime = 1h", "action = " + npm_action])
        jail("networkhelper-npm-scan", ["filter = networkhelper-npm-scan", "logpath = " + logs, "backend = auto",
                                        "maxretry = 3", "findtime = 1h", "bantime = 1d", "action = " + npm_action])
    if det["proxmox"] and det["journal"]:
        jail("networkhelper-proxmox", ["filter = networkhelper-proxmox", "backend = systemd", "port = https,http,8006",
                                       "maxretry = 3", "findtime = 10m", "bantime = 1h", "banaction = " + multi])
    out.extend(["[%s]" % F2B_SYNC_JAIL, "# Keine eigene Erkennung: Der Agent sperrt hier, was NetworkHelper sperrt.",
                "enabled = true", "ignoreip = " + ignore, "filter = networkhelper", "logpath = " + F2B_MANUAL_LOG, "backend = auto",
                "maxretry = 1", "bantime = -1", "action = " + (npm_action if det["npm_logs"] else allports), ""])
    return "\n".join(out)


def f2b_client(*args, timeout=20):
    p = subprocess.run(["fail2ban-client"] + list(args), capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def f2b_parse_jail(text):
    """Ausgabe von `fail2ban-client status <jail>` in Zahlen und Liste."""
    def num(label):
        m = re.search(label + r":\s*(\d+)", text)
        return int(m.group(1)) if m else 0
    m = re.search(r"Banned IP list:\s*(.*)", text)
    ips = [x for x in (m.group(1).split() if m else []) if F2B_IP_RE.match(x)]
    return {"failed": num("Currently failed"), "total_failed": num("Total failed"), "banned": num("Currently banned"),
            "total_banned": num("Total banned"), "ips": ips[:500]}


def f2b_status():
    if not shutil.which("fail2ban-client"):
        return {"installed": False}
    out = {"installed": True, "managed": os.path.exists(os.path.join(F2B_DIR, F2B_JAIL_FILE)), "jails": []}
    try:
        code, text = f2b_client("ping", timeout=8)
        out["running"] = code == 0 and "pong" in text
        if not out["running"]:
            out["error"] = text.strip()[-200:] or "fail2ban läuft nicht"
            return out
        code, text = f2b_client("version", timeout=8)
        out["version"] = text.strip().splitlines()[-1][:20] if code == 0 and text.strip() else None
        code, text = f2b_client("status")
        m = re.search(r"Jail list:\s*(.*)", text)
        names = [n.strip() for n in (m.group(1).split(",") if m else []) if n.strip()]
        for name in names[:30]:
            code, jt = f2b_client("status", name)
            if code == 0:
                out["jails"].append(dict(name=name, **f2b_parse_jail(jt)))
    except (OSError, subprocess.SubprocessError) as e:
        out["error"] = str(e)[:200]
    return out


class Fail2banSync:
    """Hält die Sperren im Jail „networkhelper“ gleich der Sperrliste von NetworkHelper und führt Entsperr-Wünsche aus."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.own_ips = set()

    def apply(self, status, blocklist, own_ips, unban):
        if not status.get("running"):
            return
        jails = {j["name"]: j for j in status.get("jails", [])}
        for req in unban or []:
            jail, ip = str(req.get("jail", "")), str(req.get("ip", ""))
            if jail in jails and F2B_JAIL_RE.match(jail) and F2B_IP_RE.match(ip):
                f2b_client("set", jail, "unbanip", ip)
                log("fail2ban: %s in %s entsperrt (Wunsch aus NetworkHelper)" % (ip, jail))
        own = {ip for ip in own_ips or [] if F2B_IP_RE.match(ip)}
        if own != self.own_ips:  # eigene IP nach einem Wechsel sofort ausnehmen
            for name in jails:
                for ip in own - self.own_ips:
                    f2b_client("set", name, "addignoreip", ip)
                    if ip in jails[name]["ips"]:
                        f2b_client("set", name, "unbanip", ip)
            self.own_ips = own
        if F2B_SYNC_JAIL not in jails:
            return
        wanted = {e for e in blocklist or [] if "/" not in e and F2B_IP_RE.match(e)} - own
        current = set(jails[F2B_SYNC_JAIL]["ips"])
        for ip in sorted(wanted - current)[:500]:
            f2b_client("set", F2B_SYNC_JAIL, "banip", ip)
        for ip in sorted(current - wanted)[:500]:
            f2b_client("set", F2B_SYNC_JAIL, "unbanip", ip)


def setup_fail2ban(cfg, remove=False):
    """Richtet fail2ban ein (oder entfernt die NetworkHelper-Teile). Läuft einmalig per install.sh --fail2ban."""
    jail_path = os.path.join(F2B_DIR, F2B_JAIL_FILE)
    filters = [os.path.join(F2B_DIR, "filter.d", n + ".conf") for n in F2B_FILTERS]
    if remove:
        for p in [jail_path] + filters:
            if os.path.exists(p):
                os.remove(p)
        if shutil.which("fail2ban-client"):
            f2b_client("reload", timeout=60)
        print("NetworkHelper-Regeln aus fail2ban entfernt (fail2ban selbst bleibt installiert).")
        return 0
    if not shutil.which("fail2ban-client"):
        if not shutil.which("apt-get"):
            print("fail2ban fehlt und apt-get ist nicht vorhanden. Bitte fail2ban von Hand installieren.")
            return 1
        print("Installiere fail2ban …")
        pkgs = ["fail2ban"] + ([] if shutil.which("nft") or shutil.which("iptables") else ["nftables"])
        subprocess.run(["apt-get", "update", "-qq"], check=False)
        if subprocess.run(["apt-get", "install", "-y", "-qq"] + pkgs, check=False).returncode != 0:
            print("Installation fehlgeschlagen.")
            return 1
    det = f2b_detect(cfg)
    os.makedirs(os.path.join(F2B_DIR, "filter.d"), exist_ok=True)
    os.makedirs(os.path.join(F2B_DIR, "jail.d"), exist_ok=True)
    for name, f in F2B_FILTERS.items():
        with open(os.path.join(F2B_DIR, "filter.d", name + ".conf"), "w", encoding="utf-8") as fh:
            fh.write("# Von NetworkHelper verwaltet: %s\n%s" % (f["about"], f["body"]))
    if not os.path.exists(F2B_MANUAL_LOG):
        open(F2B_MANUAL_LOG, "a").close()
    with open(jail_path, "w", encoding="utf-8") as fh:
        fh.write(f2b_jail_config(det, cfg.get("own_ips") or []))
    subprocess.run(["systemctl", "enable", "--now", "fail2ban"], check=False, capture_output=True)
    code, text = f2b_client("reload", timeout=60)
    if code != 0:
        subprocess.run(["systemctl", "restart", "fail2ban"], check=False)
        time.sleep(3)
        code, text = f2b_client("ping")
    print("fail2ban eingerichtet: SSH %s, Webseiten %s, Proxmox %s." % (
        "ja" if det["sshd"] else "nein (kein sshd)", "ja" if det["npm_logs"] else "nein (kein Proxy Manager)",
        "ja" if det["proxmox"] else "nein"))
    if code != 0:
        print("Achtung: fail2ban meldet einen Fehler: " + text.strip()[-300:])
        return 1
    return 0


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

    @staticmethod
    def _ensure_include(path, line):
        inc = read_first(path, "")
        if line not in inc:
            with open(path, "a", encoding="utf-8") as f:
                f.write(("\n" if inc and not inc.endswith("\n") else "") + line + "\n")

    @staticmethod
    def _restore(path, old):
        if old is None:
            if os.path.exists(path):
                os.remove(path)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(old)

    def apply(self, entries, digest, http_conf=None, server_snippet=""):
        """entries: deny-Adressen; http_conf: Text für den http-Block (geo/map) oder None; server_snippet: Prüfung je Host."""
        if not self.cfg.get("enforce_blocks"):
            return
        if digest == self.applied:
            return
        target = os.path.join(self.custom, BLOCK_FILE)
        include = os.path.join(self.custom, "server_proxy.conf")
        http_target = os.path.join(self.custom, HTTP_FILE)
        http_include = os.path.join(self.custom, "http_top.conf")
        try:
            os.makedirs(self.custom, exist_ok=True)
            old = read_first(target, None)
            old_http = read_first(http_target, None)
            if http_conf is None:
                server_snippet = ""  # ohne http-Teil keine Variablen, sonst schlägt nginx -t fehl
            body = "# Von NetworkHelper verwaltet, wird überschrieben. Stand: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S")
            body += "".join("deny %s;\n" % e for e in entries if re.fullmatch(r"[0-9a-fA-F:./]+", e))
            body += server_snippet or ""
            if http_conf is not None:
                with open(http_target + ".tmp", "w", encoding="utf-8") as f:
                    f.write(http_conf)
                os.replace(http_target + ".tmp", http_target)
                self._ensure_include(http_include, HTTP_INCLUDE_LINE)
            elif old_http is not None:
                with open(http_target, "w", encoding="utf-8") as f:
                    f.write("# NetworkHelper: keine Länder- oder Listen-Sperren aktiv\n")
            with open(target + ".tmp", "w", encoding="utf-8") as f:
                f.write(body)
            os.replace(target + ".tmp", target)
            self._ensure_include(include, INCLUDE_LINE)
            code, out = self._run(self._nginx("-t"))
            if code != 0:
                self._restore(target, old)
                self._restore(http_target, old_http)
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
            self.status = "%d %s gesperrt%s" % (len(entries), "Adresse" if len(entries) == 1 else "Adressen",
                                                 ", Länder-/Listen-Sperren aktiv" if server_snippet else "")
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
    auth = AuthWatcher()
    f2b = Fail2banSync(cfg)
    inventory = Inventory(cfg, api) if cfg.get("inventory", True) else None
    if inventory:
        inventory.start()
    updater = None
    if cfg.get("allow_updates"):
        updater = Updater(api, inventory)
        updater.start()
    next_watch = time.time() + 20
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
                f2b_st = f2b_status()
                res = api.post("/state", {
                    "fail2ban": f2b_st,
                    "hostname": socket.gethostname(), "version": VERSION, "info": system_info(),
                    "established": est, "listening": listen, "log_files": tailer.describe(),
                    "enforce_blocks": bool(cfg.get("enforce_blocks")), "block_status": blocker.status[:300],
                    "allow_updates": bool(updater),
                })
                if updater and res.get("actions"):
                    updater.add(res["actions"])
                http_conf = None
                if cfg.get("enforce_blocks") and res.get("http_conf_hash") and res.get("blocklist_hash") != blocker.applied:
                    http_conf = api.get_text(cfg["server"] + "/api/agent/http-conf")
                blocker.apply(res.get("blocklist", []), res.get("blocklist_hash"), http_conf, res.get("server_snippet") or "")
                interval = max(10, int(res.get("interval") or interval))
                next_state = time.time() + interval
                try:
                    f2b.apply(f2b_st, res.get("blocklist", []), res.get("own_ips", []), res.get("f2b_unban", []))
                except (OSError, subprocess.SubprocessError) as e:
                    log("fail2ban-Abgleich fehlgeschlagen: %s" % e)
                self_update(api, cfg, res.get("agent_version"))
            if cfg.get("watch", True) and time.time() >= next_watch:
                api.post("/watch", watch_snapshot(auth), timeout=60)
                next_watch = time.time() + max(60, int(cfg.get("watch_interval") or 300))
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
        print(json.dumps({"files": t.files(), "connections": connections()[0][:5], "info": system_info(),
                          "watch": {"users": login_users(), "files": len(file_hashes())}}, indent=2))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] in ("--setup-fail2ban", "--remove-fail2ban"):
        c = load_config()
        try:  # eigene öffentliche IP gleich mit ausnehmen
            c["own_ips"] = json.loads(Api(c).get_text(c["server"] + "/api/agent/own-ips", timeout=15)).get("own_ips", [])
        except Exception:  # noqa: BLE001
            c["own_ips"] = []
        sys.exit(setup_fail2ban(c, remove=sys.argv[1] == "--remove-fail2ban"))
    if len(sys.argv) > 1 and sys.argv[1] == "--inventory-now":
        c = load_config()
        inv = Inventory(c, Api(c))
        tg = inv.collect()
        print(json.dumps([{k: (len(v) if k == "packages" and v else v) for k, v in t.items()} for t in tg], indent=2))
        if "--send" in sys.argv:
            print(Api(c).post("/inventory", {"targets": tg, "complete": True, "syft": bool(inv.syft)}, timeout=180))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(VERSION)
        sys.exit(0)
    main()
