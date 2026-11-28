"""„Das war ich“: befristete Ausnahme."""
import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/trust.db")

from app.database import Base, SessionLocal, engine  # noqa: E402
from app import trusted, fail2ban  # noqa: E402


def test_trust_and_own_ips():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        assert not trusted.is_trusted(db, "197.211.186.142")
        trusted.add(db, "197.211.186.142")
        assert trusted.is_trusted(db, "197.211.186.142")
        assert "197.211.186.142" in fail2ban.own_ips(db)
        trusted.add(db, "203.0.113.9", hours=-1)
        assert not trusted.is_trusted(db, "203.0.113.9")
