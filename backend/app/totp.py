"""Zwei-Faktor-Anmeldung mit Einmalcodes aus einer Authenticator-App (TOTP, RFC 6238) und Wiederherstellungscodes.

Das Geheimnis wird verschlüsselt gespeichert (Schlüssel abgeleitet aus SECRET_KEY). Wiederherstellungscodes werden
nur als Hash gespeichert und sind je einmal gültig. Ein Code wird nach erfolgreicher Anmeldung nicht ein zweites Mal
angenommen (Schutz gegen Wiederverwendung).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

ISSUER = "NetworkHelper"
STEP = 30
DIGITS = 6
WINDOW = 1  # ein Zeitschritt vor und zurück (Uhr des Handys darf etwas abweichen)
RECOVERY_COUNT = 10


def _fernet() -> Fernet:
    key = hashlib.sha256(("networkhelper-2fa:" + settings.secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:  # SECRET_KEY geändert: 2FA muss neu eingerichtet werden
        return None


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // STEP)


def verify(secret: str, code: str, last_step: int | None = None, now: float | None = None) -> int | None:
    """Gibt den passenden Zeitschritt zurück oder None. Bereits benutzte Schritte (<= last_step) gelten nicht."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    step = current_step(now)
    for s in range(step - WINDOW, step + WINDOW + 1):
        if last_step is not None and s <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, s), code):
            return s
    return None


def uri(secret: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}", safe=":@")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def qr_svg(data: str) -> str:
    import segno
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="svg", scale=5, border=2, xmldecl=False, svgns=True, dark="#000", light="#fff")
    return buf.getvalue().decode()


def _norm_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _hash_recovery(code: str) -> str:
    return hashlib.sha256(("nh-recovery:" + _norm_recovery(code)).encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], str]:
    """(Codes zum einmaligen Anzeigen, JSON mit Hashes zum Speichern)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # ohne leicht verwechselbare Zeichen
    codes = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, json.dumps([_hash_recovery(c) for c in codes])


def use_recovery(stored: str | None, code: str) -> str | None:
    """Prüft einen Wiederherstellungscode. Gibt das neue JSON (ohne den Code) zurück oder None, wenn ungültig."""
    if len(_norm_recovery(code)) != 10:
        return None
    try:
        hashes = json.loads(stored) if stored else []
    except ValueError:
        return None
    h = _hash_recovery(code)
    for i, existing in enumerate(hashes):
        if hmac.compare_digest(existing, h):
            return json.dumps(hashes[:i] + hashes[i + 1:])
    return None


def recovery_left(stored: str | None) -> int:
    try:
        return len(json.loads(stored)) if stored else 0
    except ValueError:
        return 0
