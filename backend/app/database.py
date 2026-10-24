import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

log = logging.getLogger("networkhelper")

connect_args = {"check_same_thread": False, "timeout": 30} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def ensure_columns() -> None:
    """Ergänzt neue, optionale Spalten in bestehenden Tabellen (einfacher Ersatz für Migrationen)."""
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                if not col.nullable:
                    log.warning("Spalte %s.%s fehlt und ist nicht optional; bitte manuell migrieren.", table.name, col.name)
                    continue
                ddl_type = col.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl_type}'))
                log.info("Spalte %s.%s hinzugefügt.", table.name, col.name)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
