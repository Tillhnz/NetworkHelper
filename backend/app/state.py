"""Kleiner Schlüssel-Wert-Speicher für Hintergrundaufgaben (JSON-Werte)."""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from .models import KeyValue


def get(db: Session, key: str, default=None):
    row = db.get(KeyValue, key)
    if row is None:
        return default
    try:
        return json.loads(row.value)
    except ValueError:
        return default


def get_with_time(db: Session, key: str) -> tuple[object, datetime | None]:
    row = db.get(KeyValue, key)
    if row is None:
        return None, None
    try:
        return json.loads(row.value), row.updated_at
    except ValueError:
        return None, row.updated_at


def put(db: Session, key: str, value, commit: bool = True) -> None:
    raw = json.dumps(value, default=str)
    row = db.get(KeyValue, key)
    if row is None:
        db.add(KeyValue(key=key, value=raw, updated_at=datetime.utcnow()))
    else:
        row.value = raw
        row.updated_at = datetime.utcnow()
    if commit:
        db.commit()
