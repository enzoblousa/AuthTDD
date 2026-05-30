"""Testes de integração do endpoint POST /oauth/token (M4).

Mapeia I1–I14 de specs/04_oauth_token.md.
Content-Type: application/x-www-form-urlencoded (httpx envia via data={}).
"""

from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from sqlalchemy import select, update

from app.config import settings
from app.models.token import AuthorizationCode, RefreshToken


def _form(data: dict, overrides: dict | None = None) -> dict:
    """Monta o payload do form a partir de authorization_code_data."""
    base = {
        "grant_type": "authorization_code",
        "code": data["code"],
        "redirect_uri": data["redirect_uri"],
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
        "code_verifier": data["code_verifier"],
    }
    if overrides:
        base.update(overrides)
    return base


# --- I1 -------------------------------------------------------------------


async def test_valid_exchange_returns_200_with_tokens(
    client, authorization_code_data
):
    """I1: troca válida → 200 com access_token e refresh_token."""
    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0


# --- I2 -------------------------------------------------------------------


async def test_access_token_is_valid_jwt_with_correct_claims(
    client, authorization_code_data
):
    """I2: access_token é JWT decodificável com claims sub, exp, iat."""
    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    access_token = response.json()["access_token"]
    payload = jwt.decode(
        access_token, settings.secret_key, algorithms=[settings.algorithm]
    )
    assert "sub" in payload
    assert "exp" in payload
    assert "iat" in payload


# --- I3 -------------------------------------------------------------------


async def test_scope_in_response_matches_authorized_scope(
    client, authorization_code_data
):
    """I3: scope na resposta é o mesmo solicitado em /authorize."""
    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    assert response.json()["scope"] == authorization_code_data["scope"]


# --- I4 -------------------------------------------------------------------


async def test_used_code_returns_invalid_grant(client, authorization_code_data):
    """I4: segundo uso do mesmo code → 400 invalid_grant."""
    form = _form(authorization_code_data)
    await client.post("/oauth/token", data=form)
    response = await client.post("/oauth/token", data=form)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I5 -------------------------------------------------------------------


async def test_wrong_code_verifier_returns_invalid_grant(
    client, authorization_code_data
):
    """I5: code_verifier incorreto → 400 invalid_grant."""
    response = await client.post(
        "/oauth/token",
        data=_form(authorization_code_data, {"code_verifier": "verifier-completamente-errado"}),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I6 -------------------------------------------------------------------


async def test_missing_code_verifier_returns_invalid_request(
    client, authorization_code_data
):
    """I6: code_verifier ausente → 400 invalid_request."""
    form = _form(authorization_code_data)
    del form["code_verifier"]
    response = await client.post("/oauth/token", data=form)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


# --- I7 -------------------------------------------------------------------


async def test_expired_code_returns_invalid_grant(
    client, authorization_code_data, db_session
):
    """I7: código com expires_at no passado → 400 invalid_grant."""
    await db_session.execute(
        update(AuthorizationCode)
        .where(AuthorizationCode.code == authorization_code_data["code"])
        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=11))
    )
    await db_session.commit()

    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I8 -------------------------------------------------------------------


async def test_different_redirect_uri_returns_invalid_grant(
    client, authorization_code_data
):
    """I8: redirect_uri diferente da usada em /authorize → 400 invalid_grant."""
    response = await client.post(
        "/oauth/token",
        data=_form(
            authorization_code_data,
            {"redirect_uri": "http://localhost:3000/other"},
        ),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I9 -------------------------------------------------------------------


async def test_wrong_client_secret_returns_invalid_client(
    client, authorization_code_data
):
    """I9: client_secret errado → 400 invalid_client."""
    response = await client.post(
        "/oauth/token",
        data=_form(authorization_code_data, {"client_secret": "wrong_secret"}),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


# --- I10 ------------------------------------------------------------------


async def test_mismatched_client_id_returns_invalid_grant(
    client, authorization_code_data, db_session
):
    """I10: code gerado por outro client → 400 invalid_grant."""
    import json

    from app.models.oauth_client import OAuthClient

    second = OAuthClient(
        client_id="second_client",
        client_secret="second_secret",
        name="Second App",
        redirect_uris=json.dumps(["http://localhost:3000/callback"]),
        scopes="openid profile email",
        is_active=True,
    )
    db_session.add(second)
    await db_session.commit()

    response = await client.post(
        "/oauth/token",
        data=_form(
            authorization_code_data,
            {"client_id": "second_client", "client_secret": "second_secret"},
        ),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I11 ------------------------------------------------------------------


async def test_wrong_grant_type_returns_unsupported_grant_type(
    client, authorization_code_data
):
    """I11: grant_type != authorization_code → 400 unsupported_grant_type."""
    response = await client.post(
        "/oauth/token",
        data=_form(authorization_code_data, {"grant_type": "password"}),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


# --- I12 ------------------------------------------------------------------


async def test_code_marked_as_used_after_exchange(
    client, authorization_code_data, db_session
):
    """I12: após troca bem-sucedida, code.used == True no banco."""
    await client.post("/oauth/token", data=_form(authorization_code_data))

    result = await db_session.execute(
        select(AuthorizationCode).where(
            AuthorizationCode.code == authorization_code_data["code"]
        )
    )
    auth_code = result.scalar_one()
    assert auth_code.used is True


# --- I13 ------------------------------------------------------------------


async def test_refresh_token_saved_in_database(
    client, authorization_code_data, db_session
):
    """I13: refresh token gerado está salvo na tabela refresh_tokens."""
    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    refresh_token_value = response.json()["refresh_token"]

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token == refresh_token_value)
    )
    rt = result.scalar_one_or_none()
    assert rt is not None


# --- I14 ------------------------------------------------------------------


async def test_refresh_token_expires_in_30_days(
    client, authorization_code_data, db_session
):
    """I14: expires_at do refresh token é aproximadamente now + 30 dias (±5min)."""
    response = await client.post(
        "/oauth/token", data=_form(authorization_code_data)
    )
    refresh_token_value = response.json()["refresh_token"]

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token == refresh_token_value)
    )
    rt = result.scalar_one()
    expires = rt.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    expected = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    diff = abs((expires - expected).total_seconds())
    assert diff < 300  # menos de 5 minutos de margem
