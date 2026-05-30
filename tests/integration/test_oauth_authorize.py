"""Testes de integração do endpoint GET /oauth/authorize (M3).

Mapeia I1–I12 de specs/03_oauth_authorize.md.
"""

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from sqlalchemy import select

from app.models.token import AuthorizationCode

_BASE = {
    "response_type": "code",
    "client_id": "test_client",
    "redirect_uri": "http://localhost:3000/callback",
    "scope": "openid",
    "state": "csrf_state_abc",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _location(response) -> str:
    return response.headers["location"]


def _query_params(location: str) -> dict:
    return parse_qs(urlparse(location).query)


# --- I1 -------------------------------------------------------------------


async def test_valid_request_returns_302(client, oauth_client, authenticated_user):
    """I1: request com todos os parâmetros corretos → 302."""
    response = await client.get(
        "/oauth/authorize",
        params=_BASE,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 302


# --- I2 -------------------------------------------------------------------


async def test_state_preserved_in_redirect(client, oauth_client, authenticated_user):
    """I2: state enviado é preservado intacto no Location."""
    response = await client.get(
        "/oauth/authorize",
        params=_BASE,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    params = _query_params(_location(response))
    assert params["state"] == ["csrf_state_abc"]


# --- I3 -------------------------------------------------------------------


async def test_code_present_in_location_header(client, oauth_client, authenticated_user):
    """I3: Location contém code= não vazio."""
    response = await client.get(
        "/oauth/authorize",
        params=_BASE,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    params = _query_params(_location(response))
    assert "code" in params
    assert len(params["code"][0]) > 0


# --- I4 -------------------------------------------------------------------


async def test_nonexistent_client_id_returns_400(client, oauth_client, authenticated_user):
    """I4: client_id inexistente → 400 (sem redirect)."""
    response = await client.get(
        "/oauth/authorize",
        params={**_BASE, "client_id": "does_not_exist"},
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 400


# --- I5 -------------------------------------------------------------------


async def test_unregistered_redirect_uri_returns_400(client, oauth_client, authenticated_user):
    """I5: redirect_uri não cadastrada no client → 400 (sem redirect)."""
    response = await client.get(
        "/oauth/authorize",
        params={**_BASE, "redirect_uri": "http://evil.com/steal"},
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 400


# --- I6 -------------------------------------------------------------------


async def test_invalid_response_type_redirects_with_error(
    client, oauth_client, authenticated_user
):
    """I6: response_type != 'code' → redirect com error=unsupported_response_type."""
    response = await client.get(
        "/oauth/authorize",
        params={**_BASE, "response_type": "token"},
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 302
    params = _query_params(_location(response))
    assert params["error"] == ["unsupported_response_type"]


# --- I7 -------------------------------------------------------------------


async def test_missing_code_challenge_returns_422(client, oauth_client, authenticated_user):
    """I7: code_challenge ausente → 422 (campo obrigatório)."""
    params = {k: v for k, v in _BASE.items() if k != "code_challenge"}
    response = await client.get(
        "/oauth/authorize",
        params=params,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 422


# --- I8 -------------------------------------------------------------------


async def test_plain_code_challenge_method_returns_error(
    client, oauth_client, authenticated_user
):
    """I8: code_challenge_method=plain → 302 com error ou 422."""
    response = await client.get(
        "/oauth/authorize",
        params={**_BASE, "code_challenge_method": "plain"},
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code in (302, 422)
    if response.status_code == 302:
        assert "error=" in _location(response)


# --- I9 -------------------------------------------------------------------


async def test_invalid_scope_redirects_with_error(client, oauth_client, authenticated_user):
    """I9: scope não registrado no client → redirect com error=invalid_scope."""
    response = await client.get(
        "/oauth/authorize",
        params={**_BASE, "scope": "admin"},
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 302
    params = _query_params(_location(response))
    assert params["error"] == ["invalid_scope"]


# --- I10 ------------------------------------------------------------------


async def test_missing_state_does_not_break(client, oauth_client, authenticated_user):
    """I10: state ausente → 302 sem state= no Location."""
    params = {k: v for k, v in _BASE.items() if k != "state"}
    response = await client.get(
        "/oauth/authorize",
        params=params,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "state=" not in _location(response)


# --- I11 ------------------------------------------------------------------


async def test_generated_code_has_future_expiration(
    client, oauth_client, authenticated_user, db_session
):
    """I11: código no banco tem expires_at no futuro."""
    response = await client.get(
        "/oauth/authorize",
        params=_BASE,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    code_value = _query_params(_location(response))["code"][0]

    result = await db_session.execute(
        select(AuthorizationCode).where(AuthorizationCode.code == code_value)
    )
    auth_code = result.scalar_one()
    expires = auth_code.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    assert expires > datetime.now(timezone.utc)


# --- I12 ------------------------------------------------------------------


async def test_generated_code_is_not_used(
    client, oauth_client, authenticated_user, db_session
):
    """I12: código recém-gerado tem used == False no banco."""
    response = await client.get(
        "/oauth/authorize",
        params=_BASE,
        headers=_auth(authenticated_user["token"]),
        follow_redirects=False,
    )
    code_value = _query_params(_location(response))["code"][0]

    result = await db_session.execute(
        select(AuthorizationCode).where(AuthorizationCode.code == code_value)
    )
    auth_code = result.scalar_one()
    assert auth_code.used is False
