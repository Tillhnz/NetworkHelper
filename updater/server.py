"""Update-Dienst für NetworkHelper.

Läuft als eigener Container ohne veröffentlichten Port. Nur das Backend erreicht ihn im internen Netz, und nur mit
dem gemeinsamen Token. Er holt per git die neue Version und baut Backend und Frontend neu. Er ändert nichts an der
Datenbank oder an der .env.
"""
import gzip
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT = "/project"
TOKEN = hashlib.sha256(("updater:" + os.environ.get("SECRET_KEY", "")).encode()).hexdigest()
BACKUPS = os.path.join(PROJECT, "backups")
KEEP_BACKUPS = 14
HEALTH_URL = "http://backend:8000/api/health"
SERVICES = ["backend", "frontend"]  # der Update-Dienst baut sich nicht selbst neu, das macht ./install.sh update

lock = threading.Lock()
job = {"state": "idle", "log": "", "started": None, "error": None, "before": None}


def run(cmd, timeout=1800, log=False):
    p = subprocess.run(cmd, cwd=PROJECT, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    if log:
        job["log"] = (job["log"] + f"$ {' '.join(cmd)}\n{out}\n")[-20000:]
    return p.returncode, out.strip()


def project_name():
    code, out = run(["docker", "inspect", "-f", '{{ index .Config.Labels "com.docker.compose.project" }}', os.environ.get("HOSTNAME", "")], 20)
    return out if code == 0 and out else None


def compose_base():
    name = project_name()
    if not name:
        raise RuntimeError("Der Projektname von Docker Compose wurde nicht gefunden.")
    return ["docker", "compose", "-p", name, "--project-directory", PROJECT]


def make_backup():
    """Sichert die Postgres-Datenbank als komprimierte SQL-Datei in backups/ und räumt alte Sicherungen auf."""
    os.makedirs(BACKUPS, exist_ok=True)
    name = datetime.now().strftime("networkhelper-%Y%m%d-%H%M%S.sql.gz")
    path = os.path.join(BACKUPS, name)
    cmd = compose_base() + ["exec", "-T", "db", "sh", "-c", 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"']
    try:
        with gzip.open(path, "wb") as out:
            p = subprocess.Popen(cmd, cwd=PROJECT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            shutil.copyfileobj(p.stdout, out)
            err = p.stderr.read().decode(errors="replace")
            if p.wait() != 0:
                raise RuntimeError("Die Datenbank konnte nicht gesichert werden: " + err[-300:])
        if os.path.getsize(path) < 200:
            raise RuntimeError("Die Sicherung ist leer.")
        os.chmod(path, 0o600)
    except Exception:
        if os.path.exists(path):
            os.remove(path)
        raise
    for old in sorted(f for f in os.listdir(BACKUPS) if f.startswith("networkhelper-"))[:-KEEP_BACKUPS]:
        os.remove(os.path.join(BACKUPS, old))
    return name


def list_backups():
    if not os.path.isdir(BACKUPS):
        return []
    out = []
    for f in sorted((f for f in os.listdir(BACKUPS) if re.fullmatch(r"networkhelper-\d{8}-\d{6}\.sql\.gz", f)), reverse=True):
        st = os.stat(os.path.join(BACKUPS, f))
        out.append({"name": f, "bytes": st.st_size, "at": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")})
    return out


def wait_healthy(seconds=150):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def version():
    code, out = run(["git", "log", "-1", "--format=%h%x09%cs%x09%s"], 20)
    if code != 0:
        return None
    h, d, s = (out.split("\t") + ["", ""])[:3]
    return {"commit": h, "date": d, "subject": s}


def status(check):
    res = {"version": version(), "job": dict(job), "behind": None, "changes": [], "check_error": None, "dirty": False}
    code, out = run(["git", "status", "--porcelain", "--untracked-files=no"], 20)
    res["dirty"] = bool(out)
    if check and job["state"] != "running":
        code, out = run(["git", "fetch", "--quiet"], 60)
        if code != 0:
            res["check_error"] = "Die neue Version konnte nicht abgefragt werden: " + out[-300:]
            return res
        code, out = run(["git", "rev-list", "--count", "HEAD..@{u}"], 20)
        if code != 0:
            res["check_error"] = "Der Ordner folgt keinem Zweig auf GitHub."
            return res
        res["behind"] = int(out or 0)
        if res["behind"]:
            _, log = run(["git", "log", "HEAD..@{u}", "--format=%cs  %s", "-n", "15"], 20)
            res["changes"] = log.splitlines()
    return res


def do_update():
    before = None
    try:
        base = compose_base()
        _, before = run(["git", "rev-parse", "HEAD"], 20)
        job["before"] = before
        job["log"] += "Sichere die Datenbank …\n"
        job["log"] += f"Sicherung: {make_backup()}\n"
        code, out = run(["git", "pull", "--ff-only"], 300, log=True)
        if code != 0:
            raise RuntimeError("git pull ist fehlgeschlagen. Lokale Änderungen im Projektordner verhindern das Update oder GitHub ist nicht erreichbar.")
        code, out = run(base + ["build", *SERVICES], 3000, log=True)
        if code != 0:
            run(["git", "reset", "--keep", before], 60, log=True)
            raise RuntimeError("Der Bau der neuen Version ist fehlgeschlagen. Die laufende Version bleibt unverändert.")
        job["state"] = "restarting"
        code, out = run(base + ["up", "-d", *SERVICES], 600, log=True)
        if code != 0 or not wait_healthy():
            job["log"] += "Die neue Version startet nicht. Gehe zur vorherigen Version zurück …\n"
            run(["git", "reset", "--keep", before], 60, log=True)
            run(base + ["build", *SERVICES], 3000, log=True)
            run(base + ["up", "-d", *SERVICES], 600, log=True)
            raise RuntimeError("Die neue Version ist nicht angesprungen. NetworkHelper läuft wieder mit der vorherigen Version. Die Datenbank-Sicherung vom Start des Updates liegt im Ordner backups.")
        job["state"] = "done"
    except Exception as e:  # Fehler für die Oberfläche festhalten
        job["state"], job["error"] = "failed", str(e)
    finally:
        lock.release()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self):
        if hmac.compare_digest(self.headers.get("X-Updater-Token", ""), TOKEN):
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        if not self._auth():
            return
        if self.path.startswith("/status"):
            self._send(200, status("check=1" in self.path))
        elif self.path == "/backups":
            self._send(200, {"items": list_backups(), "busy": job["state"] in ("running", "restarting")})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        if self.path == "/backups":
            if not lock.acquire(blocking=False):
                return self._send(409, {"error": "Es läuft gerade ein Update."})
            try:
                return self._send(201, {"name": make_backup()})
            except Exception as e:
                return self._send(502, {"error": str(e)})
            finally:
                lock.release()
        if self.path != "/update":
            return self._send(404, {"error": "not found"})
        if not lock.acquire(blocking=False):
            return self._send(409, {"error": "Es läuft bereits ein Update."})
        job.update(state="running", log="", error=None, started=None)
        threading.Thread(target=do_update, daemon=True).start()
        self._send(202, {"ok": True})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
