import os
import tempfile

# Vor dem ersten Import der App setzen: eigene SQLite-Datei, keine Hintergrundaufgaben, offene Registrierung
os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/test.db")
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ["BACKGROUND_JOBS"] = "false"
os.environ["ALLOW_REGISTRATION"] = "true"
os.environ["GEOIP_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_ratelimit():
    from app import ratelimit
    ratelimit.reset()
    yield
    ratelimit.reset()


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin(client):
    r = client.post("/api/auth/register", json={"email": "admin@example.de", "password": "geheim1234"})
    assert r.status_code == 201, r.text
    client.cookies.clear()  # Tests nutzen den Bearer-Kopf; Cookies prüft test_cookie_session gezielt
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(autouse=True)
def _no_cookies(request):
    if "client" in request.fixturenames:
        request.getfixturevalue("client").cookies.clear()
    yield
