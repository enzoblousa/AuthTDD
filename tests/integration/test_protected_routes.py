"""Testes de integração de GET /users/me — rotas protegidas e scopes (M6).

Mapeia I1–I8 de specs/06_protected_routes.md.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.token import RevokedToken
from app.services.token_service import create_access_token, decode_access_token


async def _token(test_user, scope: str = "openid profile") -> str:
    """Cria um access token com o scope especificado para o test_user."""
    return create_access_token({"sub": str(test_user.id), "scope": scope})


# --- I1 -------------------------------------------------------------------


async def test_get_me_with_valid_token_returns_200(client, test_user):
    """I1: token válido com scope profile → 200 com dados do usuário."""
    token = await _token(test_user)
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == test_user.email
    assert body["name"] == test_user.name
    assert body["is_active"] is True


# --- I2 -------------------------------------------------------------------


async def test_get_me_without_auth_header_returns_401(client, test_user):
    """I2: sem header Authorization → 401."""
    response = await client.get("/users/me")
    assert response.status_code == 401


# --- I3 -------------------------------------------------------------------


async def test_get_me_with_malformed_token_returns_401(client, test_user):
    """I3: token malformado → 401."""
    response = await client.get(
        "/users/me", headers={"Authorization": "Bearer not_a_jwt_at_all"}
    )
    assert response.status_code == 401


# --- I4 -------------------------------------------------------------------


async def test_get_me_with_expired_token_returns_401(client, test_user):
    """I4: token expirado → 401."""
    token = create_access_token(
        {"sub": str(test_user.id), "scope": "openid profile"},
        expires_delta=timedelta(seconds=-1),
    )
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


# --- I5 -------------------------------------------------------------------


async def test_get_me_without_profile_scope_returns_403(client, test_user):
    """I5: token sem scope 'profile' → 403."""
    token = await _token(test_user, scope="openid")
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


# --- I6 -------------------------------------------------------------------


async def test_get_me_with_revoked_token_returns_401(client, test_user, db_session):
    """I6: jti na blacklist → 401."""
    token = await _token(test_user)
    payload = decode_access_token(token)
    jti = payload["jti"]

    revoked = RevokedToken(
        jti=jti,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(revoked)
    await db_session.commit()

    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


# --- I7 -------------------------------------------------------------------


async def test_response_contains_token_scopes(client, test_user):
    """I7: corpo da resposta inclui o campo 'scopes' com os scopes do token."""
    token = await _token(test_user, scope="openid profile")
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    scopes = response.json()["scopes"]
    assert "openid" in scopes
    assert "profile" in scopes


# --- I8 -------------------------------------------------------------------


async def test_inactive_user_returns_401(client, db_session):
    """I8: usuário com is_active=False → 401."""
    from app.core.security import hash_password
    from app.models.user import User

    inactive = User(
        name="Inactive User",
        email="inactive2@example.com",
        hashed_password=hash_password("Senha1234"),
        is_active=False,
    )
    db_session.add(inactive)
    await db_session.commit()
    await db_session.refresh(inactive)

    token = create_access_token(
        {"sub": str(inactive.id), "scope": "openid profile"}
    )
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
