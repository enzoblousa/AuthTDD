"""Geração e validação de tokens JWT assinados com HS256 (M2)."""

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt  # noqa: F401  (JWTError reexportado para uso externo)

from app.config import settings


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Gera um JWT assinado com os dados fornecidos.

    `iat` é armazenado como unix timestamp inteiro para que a diferença
    (exp - iat) seja exata em segundos (sem arredondamentos de float).
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {**data, "iat": int(now.timestamp()), "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict:
    """Decodifica e valida um JWT. Lança JWTError se inválido ou expirado."""
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def access_token_expires_in() -> int:
    """Segundos de validade do access token (para o campo expires_in da resposta)."""
    return settings.access_token_expire_minutes * 60
