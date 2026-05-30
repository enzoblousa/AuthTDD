"""Testes de integração do endpoint POST /oauth/token com grant_type=refresh_token (M5).

Mapeia I1–I10 de specs/05_token_refresh.md.
"""

from datetime import datetime, timedelta, timezone

from jose import jwt
from sqlalchemy import select, update

from app.config import settings
from app.models.token import RefreshToken


def _form(data: dict, overrides: dict | None = None) -> dict:
    base = {
        "grant_type": "refresh_token",
        "refresh_token": data["refresh_token"],
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    if overrides:
        base.update(overrides)
    return base


# --- I1 -------------------------------------------------------------------


async def test_valid_refresh_returns_200_with_new_tokens(client, valid_refresh_token):
    """I1: refresh válido → 200 com novo access_token e refresh_token."""
    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0


# --- I2 -------------------------------------------------------------------


async def test_new_access_token_is_valid_jwt(client, valid_refresh_token):
    """I2: novo access_token é JWT decodificável."""
    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    access_token = response.json()["access_token"]
    payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
    assert "sub" in payload
    assert "exp" in payload


# --- I3 -------------------------------------------------------------------


async def test_new_refresh_token_differs_from_original(client, valid_refresh_token):
    """I3: novo refresh_token != token original."""
    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert response.json()["refresh_token"] != valid_refresh_token["refresh_token"]


# --- I4 -------------------------------------------------------------------


async def test_old_refresh_token_invalid_after_rotation(client, valid_refresh_token):
    """I4: token antigo inválido após rotação → 400 invalid_grant."""
    await client.post("/oauth/token", data=_form(valid_refresh_token))
    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I5 -------------------------------------------------------------------


async def test_new_access_token_has_correct_scope(client, valid_refresh_token):
    """I5: novo access token herda o scope original do refresh token."""
    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert response.json()["scope"] == valid_refresh_token["scope"]


# --- I6 -------------------------------------------------------------------


async def test_expired_refresh_token_returns_invalid_grant(
    client, valid_refresh_token, db_session
):
    """I6: refresh token com expires_at no passado → 400 invalid_grant."""
    await db_session.execute(
        update(RefreshToken)
        .where(RefreshToken.token == valid_refresh_token["refresh_token"])
        .values(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    )
    await db_session.commit()

    response = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --- I7 -------------------------------------------------------------------


async def test_revoked_token_triggers_family_revocation(
    client, valid_refresh_token, db_session
):
    """I7: token já revogado → 400 + toda família revogada."""
    # Usa o token uma vez → cria novo token B (antigo fica revogado)
    r1 = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert r1.status_code == 200
    new_token_value = r1.json()["refresh_token"]

    # Tenta usar o token antigo (já revogado) → theft detection
    r2 = await client.post("/oauth/token", data=_form(valid_refresh_token))
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"

    # Token novo (B) também deve estar revogado pela detecção de roubo
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token == new_token_value)
    )
    new_rt = result.scalar_one()
    await db_session.refresh(new_rt)
    assert new_rt.revoked is True


# --- I8 -------------------------------------------------------------------


async def test_wrong_client_secret_returns_invalid_client(client, valid_refresh_token):
    """I8: client_secret errado → 400 invalid_client."""
    response = await client.post(
        "/oauth/token",
        data=_form(valid_refresh_token, {"client_secret": "wrong_secret"}),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


# --- I9 -------------------------------------------------------------------


async def test_client_id_mismatch_returns_invalid_client(
    client, valid_refresh_token, db_session
):
    """I9: token pertence a outro client → 400 invalid_client."""
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
            valid_refresh_token,
            {"client_id": "second_client", "client_secret": "second_secret"},
        ),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


# --- I10 ------------------------------------------------------------------


async def test_missing_refresh_token_field_returns_422(client, valid_refresh_token):
    """I10: grant_type=refresh_token sem o campo refresh_token → 422."""
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": valid_refresh_token["client_id"],
            "client_secret": valid_refresh_token["client_secret"],
        },
    )
    assert response.status_code == 422
