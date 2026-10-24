"""Verwaltungsprotokoll: wer hat wann welche Verwaltungsaktion ausgelöst. Es enthält keine persönlichen Inhalte."""
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import AuditEntry

KEEP = 1000


def record(db: Session, actor: str, action: str, detail: str = "") -> None:
    """Schreibt einen Eintrag und hält das Protokoll auf die letzten KEEP Einträge begrenzt."""
    db.add(AuditEntry(actor=actor[:255], action=action[:40], detail=(detail or None) and detail[:300]))
    db.commit()
    oldest_kept = db.scalar(select(AuditEntry.id).order_by(AuditEntry.id.desc()).offset(KEEP - 1).limit(1))
    if oldest_kept:
        db.execute(delete(AuditEntry).where(AuditEntry.id < oldest_kept))
        db.commit()
