from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User

bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def create_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=settings.token_expire_days)
    claims = {"sub": str(user.id), "exp": exp, "tv": user.token_version or 0}
    return jwt.encode(claims, settings.secret_key, algorithm="HS256")


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Nicht angemeldet")
    if creds is None:
        raise unauthorized
    try:
        payload = jwt.decode(creds.credentials, settings.secret_key, algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise unauthorized
    if user is None or payload.get("tv", 0) != (user.token_version or 0) or user.active is False:
        raise unauthorized  # abgemeldet (Überall abmelden / Passwort geändert), gesperrt oder Konto gelöscht
    return user


def is_admin(db: Session, user: User) -> bool:
    return user.role == "admin"


def require_admin(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
    if not is_admin(db, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Nur für den Administrator")
    return user
