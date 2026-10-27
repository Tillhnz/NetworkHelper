"""Prüft die fail2ban-Teile des Agenten mit echtem fail2ban (CI: apt-get install fail2ban).

    python tools/fail2ban_selftest.py            # nutzt fail2ban-regex/fail2ban-client aus PATH und /etc/fail2ban
    F2B_BIN=/pfad/bin F2B_CONFIG=/pfad/config python tools/fail2ban_selftest.py
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("agent", os.path.join(ROOT, "agent", "nh-agent.py"))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

BIN = os.environ.get("F2B_BIN", "")
REGEX = [sys.executable, os.path.join(BIN, "fail2ban-regex")] if BIN else ["fail2ban-regex"]
CLIENT = [sys.executable, os.path.join(BIN, "fail2ban-client")] if BIN else ["fail2ban-client"]
SRC_CONFIG = os.environ.get("F2B_CONFIG", "/etc/fail2ban")

LINES = {
    "networkhelper-npm-auth": {
        True: ['[27/Oct/2026:20:10:01 +0100] - 401 401 - POST https cloud.example.de "/index.php/login" [Client 45.9.9.1] [Length 512] [Gzip -] [Sent-to 192.168.1.20] "Mozilla/5.0" "-"',
               '[27/Oct/2026:20:10:02 +0100] - 403 403 - GET https vault.example.de "/identity/connect/token" [Client 2001:db8::7] [Length 0] [Gzip -] [Sent-to 192.168.1.21] "python" "-"',
               '[27/Oct/2026:20:10:03 +0100] 401 - GET https a.example "/x" [Client 1.2.3.4] [Length 5] [Gzip 2.5] "ua" "-"'],
        False: ['[27/Oct/2026:20:10:04 +0100] - 200 200 - GET https cloud.example.de "/index.php/login" [Client 45.9.9.2] [Length 512] [Gzip -] [Sent-to 192.168.1.20] "Mozilla/5.0" "-"',
                '[27/Oct/2026:20:10:08 +0100] - - 301 - GET http nas.example.de "/" [Client 45.9.9.6] [Length 166] [Gzip -] [Sent-to nas] "curl/8" "-"'],
    },
    "networkhelper-npm-scan": {
        True: ['[27/Oct/2026:20:10:05 +0100] - 404 404 - GET https cloud.example.de "/.env" [Client 45.9.9.3] [Length 150] [Gzip -] [Sent-to 192.168.1.20] "zgrab" "-"',
               '[27/Oct/2026:20:10:06 +0100] - 404 404 - GET https bike.example.de "/wp-login.php?x=1" [Client 45.9.9.4] [Length 150] [Gzip -] [Sent-to 192.168.1.22] "Mozilla" "-"'],
        False: ['[27/Oct/2026:20:10:07 +0100] - 200 200 - GET https blog.example.de "/wp-login.php" [Client 45.9.9.5] [Length 4000] [Gzip -] [Sent-to 192.168.1.23] "Mozilla" "-"',
                '[27/Oct/2026:20:10:09 +0100] - 404 404 - GET https cloud.example.de "/favicon.ico" [Client 45.9.9.7] [Length 150] [Gzip -] [Sent-to 192.168.1.20] "Mozilla" "-"'],
    },
    "networkhelper-proxmox": {
        True: ["Oct 27 20:11:00 pve pvedaemon[1234]: authentication failure; rhost=::ffff:45.9.9.9 user=root@pam msg=Authentication failure",
               "Oct 27 20:11:01 pve pvedaemon[1234]: authentication verification failure; rhost=45.9.9.8 user=till@pve msg=invalid credentials"],
        False: ["Oct 27 20:11:02 pve pvedaemon[1234]: <root@pam> successful auth for user 'root@pam'"],
    },
}


def main() -> int:
    work = tempfile.mkdtemp()
    cfg = os.path.join(work, "fail2ban")
    shutil.copytree(SRC_CONFIG, cfg)
    jd = os.path.join(cfg, "jail.d")
    os.makedirs(jd, exist_ok=True)
    for f in os.listdir(jd):  # Vorgaben der Distribution (z. B. defaults-debian.conf) für den Test weglassen
        os.remove(os.path.join(jd, f))
    for name, f in agent.F2B_FILTERS.items():
        with open(os.path.join(cfg, "filter.d", name + ".conf"), "w") as fh:
            fh.write(f["body"])
    failed = 0
    for name, cases in LINES.items():
        for expect, lines in cases.items():
            for line in lines:
                log = os.path.join(work, "t.log")
                with open(log, "w") as fh:
                    fh.write(line + "\n")
                out = subprocess.run(REGEX + ["-c", cfg, log, os.path.join(cfg, "filter.d", name + ".conf")],
                                     capture_output=True, text=True).stdout
                hit = "1 matched" in out
                if hit != expect:
                    failed += 1
                    print(f"FEHLER {name}: erwartet {'Treffer' if expect else 'kein Treffer'}: {line}")
    npm = os.path.join(work, "npm", "logs")
    os.makedirs(npm)
    open(os.path.join(npm, "proxy-host-1_access.log"), "w").close()
    agent.F2B_MANUAL_LOG = os.path.join(work, "manual.log")
    open(agent.F2B_MANUAL_LOG, "w").close()
    for label, det in {"docker": dict(sshd=True, journal=True, npm_logs=npm, npm_docker=True, proxmox=False, nft=False),
                       "pve": dict(sshd=True, journal=True, npm_logs="", npm_docker=False, proxmox=True, nft=True),
                       "native": dict(sshd=False, journal=False, npm_logs=npm, npm_docker=False, proxmox=False, nft=True)}.items():
        with open(os.path.join(cfg, "jail.d", "networkhelper.local"), "w") as fh:
            fh.write(agent.f2b_jail_config(det, ["79.208.166.153"]))
        p = subprocess.run(CLIENT + ["-c", cfg, "-d"], capture_output=True, text=True)
        dump = p.stdout + p.stderr
        jails = [l for l in dump.splitlines() if l.startswith("['add'")]
        if p.returncode != 0 or "ERROR" in dump or not any("'networkhelper'" in j for j in jails):
            failed += 1
            print(f"FEHLER Konfiguration {label}:\n{dump[-1500:]}")
        else:
            print(f"ok Konfiguration {label}: {len(jails)} Jails")
    print("fail2ban-Selbsttest:", "OK" if not failed else f"{failed} Fehler")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
