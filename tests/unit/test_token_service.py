"""Testes unitários do serviço de tokens JWT (M2) e PKCE + refresh token (M4).

M2: U1–U6 — specs/02_login.md
M4: U1–U5 — specs/04_oauth_token.md
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


# =============================================================================
# M4 — PKCE (U1–U3) e Refresh Token (U4–U5)
# =============================================================================

import base64
import hashlib
import secrets as _secrets

from app.core.security import verify_pkce
from app.services.oauth_service import generate_refresh_token

_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_CODE_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(_CODE_VERIFIER.encode()).digest())
    .rstrip(b"=")
    .decode()
)


# --- M4·U1: verify_pkce com verifier correto retorna True -------------------


def test_verify_pkce_with_correct_verifier_returns_true():
    """M4·U1: verify_pkce(verifier_correto, challenge) == True."""
    assert verify_pkce(_CODE_VERIFIER, _CODE_CHALLENGE) is True


# --- M4·U2: verify_pkce com verifier errado retorna False -------------------


def test_verify_pkce_with_wrong_verifier_returns_false():
    """M4·U2: verify_pkce(verifier_errado, challenge) == False."""
    assert verify_pkce("verifier-completamente-errado", _CODE_CHALLENGE) is False


# --- M4·U3: verify_pkce com verifier vazio retorna False --------------------


def test_verify_pkce_with_empty_verifier_returns_false():
    """M4·U3: verify_pkce("", challenge) == False."""
    assert verify_pkce("", _CODE_CHALLENGE) is False


# --- M4·U4: refresh token gerado não é JWT ----------------------------------


async def test_refresh_token_is_opaque_not_jwt(db_session):
    """M4·U4: refresh token não tem formato JWT (3 segmentos separados por '.')."""
    rt = await generate_refresh_token(
        db=db_session,
        user_id="user-id-123",
        client_id="test_client",
        scope="openid",
    )
    assert rt.token.count(".") != 2


# --- M4·U5: dois refresh tokens gerados são diferentes ---------------------


async def test_two_refresh_tokens_are_different(db_session):
    """M4·U5: dois refresh tokens consecutivos são distintos."""
    rt1 = await generate_refresh_token(
        db=db_session, user_id="user-id-123", client_id="test_client", scope="openid"
    )
    rt2 = await generate_refresh_token(
        db=db_session, user_id="user-id-123", client_id="test_client", scope="openid"
    )
    assert rt1.token != rt2.token


# =============================================================================
# M5 — Rotação de Refresh Token (U1–U5)
# =============================================================================

import pytest_asyncio as _pasyncio

from app.models.token import RefreshToken as _RT
from app.services.oauth_service import rotate_refresh_token


@_pasyncio.fixture
async def _old_rt(db_session):
    """RefreshToken base para os testes de rotação (M5)."""
    from datetime import datetime, timedelta, timezone

    rt = _RT(
        token=_secrets.token_urlsafe(32),
        user_id="user-id-123",
        client_id="test_client",
        scope="openid profile",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        revoked=False,
    )
    db_session.add(rt)
    await db_session.commit()
    await db_session.refresh(rt)
    return rt


# --- M5·U1: token novo é diferente do antigo --------------------------------


async def test_rotate_produces_different_token(_old_rt, db_session):
    """M5·U1: token rotacionado != token original."""
    new_rt = await rotate_refresh_token(db_session, _old_rt)
    assert new_rt.token != _old_rt.token


# --- M5·U2: token antigo marcado como revogado ------------------------------


async def test_rotate_revokes_old_token(_old_rt, db_session):
    """M5·U2: old_rt.revoked == True após rotação."""
    await rotate_refresh_token(db_session, _old_rt)
    assert _old_rt.revoked is True


# --- M5·U3: replaced_by aponta para o novo token ----------------------------


async def test_rotate_sets_replaced_by(_old_rt, db_session):
    """M5·U3: old_rt.replaced_by == new_rt.id."""
    new_rt = await rotate_refresh_token(db_session, _old_rt)
    assert _old_rt.replaced_by == new_rt.id


# --- M5·U4: novo token herda scope ------------------------------------------


async def test_rotate_inherits_scope(_old_rt, db_session):
    """M5·U4: new_rt.scope == old_rt.scope."""
    new_rt = await rotate_refresh_token(db_session, _old_rt)
    assert new_rt.scope == _old_rt.scope


# --- M5·U5: novo token herda expires_at -------------------------------------


async def test_rotate_inherits_expires_at(_old_rt, db_session):
    """M5·U5: new_rt.expires_at == old_rt.expires_at (não renova validade)."""
    from datetime import timezone

    new_rt = await rotate_refresh_token(db_session, _old_rt)

    def _utc(dt):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    diff = abs((_utc(new_rt.expires_at) - _utc(_old_rt.expires_at)).total_seconds())
    assert diff < 1


# =============================================================================
# M7 — Revogação de tokens (U1–U4)
# =============================================================================

import json as _json

from app.models.oauth_client import OAuthClient as _OAuthClient
from app.models.token import RevokedToken as _RevokedToken
from app.services.oauth_service import revoke_token
from app.services.token_service import decode_token_claims


@_pasyncio.fixture
async def _revoke_client(db_session):
    """OAuthClient mínimo para testes de revoke (M7)."""
    c = _OAuthClient(
        client_id="revoke_client",
        client_secret="revoke_secret",
        name="Revoke Test App",
        redirect_uris=_json.dumps(["http://localhost/cb"]),
        scopes="openid profile",
        is_active=True,
    )
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)
    return c


@_pasyncio.fixture
async def _rt_with_jti(db_session, _revoke_client):
    """RefreshToken com access_token_jti definido (para testes de cascade M7)."""
    from datetime import datetime, timedelta, timezone

    from app.services.token_service import create_access_token

    at = create_access_token({"sub": "uid-123", "scope": "openid profile"})
    at_jti = decode_token_claims(at).get("jti")

    rt = _RT(
        token=_secrets.token_urlsafe(32),
        user_id="uid-123",
        client_id="revoke_client",
        scope="openid profile",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        revoked=False,
        access_token_jti=at_jti,
    )
    db_session.add(rt)
    await db_session.commit()
    await db_session.refresh(rt)
    return rt, at, at_jti


# --- M7·U1: revogar refresh token marca como revogado -----------------------


async def test_revoke_refresh_token_marks_as_revoked(_rt_with_jti, _revoke_client, db_session):
    """M7·U1: revoke(refresh_token) → rt.revoked == True."""
    rt, _at, _jti = _rt_with_jti
    await revoke_token(db_session, rt.token, "refresh_token", _revoke_client)
    await db_session.refresh(rt)
    assert rt.revoked is True


# --- M7·U2: revogar refresh token invalida access token derivado -------------


async def test_revoke_refresh_token_blacklists_access_jti(
    _rt_with_jti, _revoke_client, db_session
):
    """M7·U2: revoke(refresh_token) → jti do access token na blacklist."""
    from sqlalchemy import select

    rt, _at, at_jti = _rt_with_jti
    await revoke_token(db_session, rt.token, "refresh_token", _revoke_client)

    result = await db_session.execute(
        select(_RevokedToken).where(_RevokedToken.jti == at_jti)
    )
    assert result.scalar_one_or_none() is not None


# --- M7·U3: revogar access token adiciona jti à blacklist -------------------


async def test_revoke_access_token_blacklists_jti(_revoke_client, db_session):
    """M7·U3: revoke(access_token) → jti presente em revoked_tokens."""
    from sqlalchemy import select
    from app.services.token_service import create_access_token

    at = create_access_token({"sub": "uid-123", "scope": "openid"})
    at_jti = decode_token_claims(at).get("jti")

    await revoke_token(db_session, at, "access_token", _revoke_client)

    result = await db_session.execute(
        select(_RevokedToken).where(_RevokedToken.jti == at_jti)
    )
    assert result.scalar_one_or_none() is not None


# --- M7·U4: token inexistente não lança exceção -----------------------------


async def test_revoke_nonexistent_token_does_not_raise(_revoke_client, db_session):
    """M7·U4: token aleatório → sem exceção (RFC 7009)."""
    await revoke_token(db_session, "token-que-nao-existe-em-lugar-nenhum", None, _revoke_client)
