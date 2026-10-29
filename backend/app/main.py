import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware

from . import geoip, scheduler, server_settings
from .config import settings
from .database import Base, SessionLocal, engine, ensure_columns
from .routers import access, adguard, admin, agents, auth, diagnose, dns, monitors, overview, security

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.secret_key in ("dev-secret-change-me", "bitte-aendern") or len(settings.secret_key) < 16:
        logging.getLogger("networkhelper").warning("SECRET_KEY ist unsicher. Setze einen langen Zufallswert (openssl rand -hex 32).")
    Base.metadata.create_all(engine)
    ensure_columns()
    with SessionLocal() as db:
        server_settings.apply_overrides(db)
    geoip.reload()
    if settings.background_jobs:
        threading.Thread(target=geoip.refresh_if_old, daemon=True, name="geoip").start()
        scheduler.start()
    yield


app = FastAPI(title="NetworkHelper", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


for r in (auth, admin, agents, access, security, monitors, dns, overview, diagnose, adguard):
    app.include_router(r.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
