"""Einfache Drosselung fehlgeschlagener Anmeldungen (im Speicher, pro Prozess).

Gezählt wird pro E-Mail-Adresse und pro Client-Adresse. Die Client-Adresse kann hinter einem Proxy
gefälscht sein, deshalb schützt vor allem die Zählung pro E-Mail. Nach einem Neustart sind die Zähler leer.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from .config import settings

WINDOW_S = 15 * 60
LIMIT_PER_EMAIL = 8
LIMIT_PER_IP = 40
REGISTER_WINDOW_S = 60 * 60
LIMIT_REGISTER_PER_IP = 10

_lock = threading.Lock()
_fails: dict[str, deque] = defaultdict(deque)


def client_ip(request: Request) -> str:
    """Adresse des Clients. Hinter Proxys ist X-Forwarded-For fälschbar, deshalb zählt nur der Eintrag, den der
    letzte vertrauenswürdige Proxy angehängt hat (TRUSTED_PROXIES = Zahl der Proxys vor dem Webserver, z. B. 1 für
    den Nginx Proxy Manager)."""
    hops = settings.trusted_proxies
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if hops > 0 and len(parts) > hops:
        return parts[-(hops + 1)]
    return request.client.host if request.client else "unbekannt"


def _prune(q: deque, now: float, window: float) -> None:
    while q and now - q[0] > window:
        q.popleft()


def _retry_after(key: str, limit: int, window: float, now: float) -> int | None:
    q = _fails.get(key)
    if not q:
        return None
    _prune(q, now, window)
    if len(q) >= limit:
        return int(window - (now - q[0])) + 1
    if not q:
        _fails.pop(key, None)
    return None


def check_login(email: str, ip: str, now: float | None = None) -> None:
    """Wirft 429, wenn zu viele Fehlversuche für diese E-Mail oder Adresse vorliegen."""
    now = time.monotonic() if now is None else now
    with _lock:
        wait = max(
            _retry_after(f"mail:{email}", LIMIT_PER_EMAIL, WINDOW_S, now) or 0,
            _retry_after(f"ip:{ip}", LIMIT_PER_IP, WINDOW_S, now) or 0,
        )
    if wait:
        raise HTTPException(429, f"Zu viele Fehlversuche. Bitte in {max(1, wait // 60)} Minuten erneut versuchen.",
                            headers={"Retry-After": str(wait)})


def record_failure(email: str, ip: str, now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    with _lock:
        _fails[f"mail:{email}"].append(now)
        _fails[f"ip:{ip}"].append(now)


def record_success(email: str) -> None:
    with _lock:
        _fails.pop(f"mail:{email}", None)


def check_register(ip: str, now: float | None = None) -> None:
    """Zählt jeden Registrierversuch; wirft 429 bei zu vielen pro Stunde."""
    now = time.monotonic() if now is None else now
    with _lock:
        wait = _retry_after(f"reg:{ip}", LIMIT_REGISTER_PER_IP, REGISTER_WINDOW_S, now)
        if not wait:
            _fails[f"reg:{ip}"].append(now)
    if wait:
        raise HTTPException(429, "Zu viele Registrierungsversuche. Bitte später erneut versuchen.",
                            headers={"Retry-After": str(wait)})


def check_reset(ip: str, email: str, now: float | None = None) -> None:
    """Drosselt Anfragen für Passwort-Links: je Adresse und je E-Mail nur wenige pro Stunde."""
    now = time.monotonic() if now is None else now
    with _lock:
        wait = max(_retry_after(f"rst-ip:{ip}", 10, REGISTER_WINDOW_S, now) or 0,
                   _retry_after(f"rst-mail:{email}", 3, REGISTER_WINDOW_S, now) or 0)
        if not wait:
            _fails[f"rst-ip:{ip}"].append(now)
            _fails[f"rst-mail:{email}"].append(now)
    if wait:
        raise HTTPException(429, "Zu viele Anfragen. Bitte später erneut versuchen.", headers={"Retry-After": str(wait)})


def reset() -> None:
    with _lock:
        _fails.clear()
