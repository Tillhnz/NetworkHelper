"""Notfall-Befehle auf dem Server, z. B. wenn der einzige Administrator sein Handy verloren hat.

    docker compose exec backend python -m app.cli reset-2fa admin@example.de
    docker compose exec backend python -m app.cli list-users
"""
import sys

from sqlalchemy import select

from .database import SessionLocal
from .models import User


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "list-users":
        with SessionLocal() as db:
            for u in db.scalars(select(User).order_by(User.id)):
                print(f"{u.id:>3}  {u.email:<40} {u.role or 'user':<6} 2FA: {'an' if u.totp_enabled else 'aus'}")
        return 0
    if len(argv) == 2 and argv[0] == "reset-2fa":
        with SessionLocal() as db:
            u = db.scalar(select(User).where(User.email == argv[1].strip().lower()))
            if u is None:
                print(f"Kein Konto mit der E-Mail {argv[1]}")
                return 1
            u.totp_enabled, u.totp_secret, u.totp_pending, u.recovery_codes, u.totp_enabled_at = False, None, None, None, None
            u.token_version = (u.token_version or 0) + 1
            db.commit()
            from . import audit
            audit.record(db, "server-konsole", "user.2fa_reset", u.email)
            print(f"Zwei-Faktor-Anmeldung für {u.email} zurückgesetzt. Anmelden geht jetzt wieder nur mit dem Passwort.")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
