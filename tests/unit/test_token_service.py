"""Testes unitários do serviço de tokens JWT (M2).

Mapeia os casos U1–U6 da spec `specs/02_login.md`.
"""

from datetime import timedelta

import pytest
from jose import JWTError, jwt

from app.config import settings
from app.services.token_service import create_access_token, decode_access_token

USER_DATA = {"sub": "550e8400-e29b-41d4-a716-446655440000", "email": "user@example.com"}


# --- U1: token gerado é string JWT válida ---------------------------------


def test_create_access_token_returns_jwt_string():
    token = create_access_token(USER_DATA)

    # JWT tem exatamente 3 segmentos separados por ponto
    assert isinstance(token, str)
    assert token.count(".") == 2


# --- U2: claims corretos no payload ---------------------------------------


def test_create_access_token_includes_correct_claims():
    token = create_access_token(USER_DATA)
    payload = decode_access_token(token)

    assert payload["sub"] == USER_DATA["sub"]
    assert payload["email"] == USER_DATA["email"]
    assert "iat" in payload
    assert "exp" in payload


# --- U3: token expira no tempo configurado --------------------------------


def test_create_access_token_expires_in_configured_time():
    token = create_access_token(USER_DATA)
    payload = decode_access_token(token)

    expected_delta = settings.access_token_expire_minutes * 60
    actual_delta = payload["exp"] - payload["iat"]

    assert actual_delta == expected_delta


def test_create_access_token_respects_custom_expires_delta():
    token = create_access_token(USER_DATA, expires_delta=timedelta(minutes=5))
    payload = decode_access_token(token)

    actual_delta = payload["exp"] - payload["iat"]
    assert actual_delta == 300  # 5 minutos em segundos


# --- U4: token expirado lança exceção -------------------------------------


def test_expired_token_raises_exception():
    # Cria token que já expirou (delta negativo)
    token = create_access_token(USER_DATA, expires_delta=timedelta(seconds=-1))

    with pytest.raises(JWTError):
        decode_access_token(token)


# --- U5: token com assinatura adulterada lança exceção --------------------


def test_tampered_token_raises_exception():
    token = create_access_token(USER_DATA)
    # Troca o último caractere para corromper a assinatura
    tampered = token[:-1] + ("X" if token[-1] != "X" else "Y")

    with pytest.raises(JWTError):
        decode_access_token(tampered)


# --- U6: SECRET_KEY diferente invalida o token ----------------------------


def test_different_secret_key_invalidates_token():
    # Gera com a chave padrão, decodifica manualmente com outra chave
    token = create_access_token(USER_DATA)

    with pytest.raises(JWTError):
        jwt.decode(token, "chave-completamente-diferente", algorithms=["HS256"])
