"""Teste E2E — Fluxo completo Authorization Code + PKCE (M1-M7).

Cobre os 9 passos descritos em specs/07_revocation.md §Teste E2E.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse


async def test_full_authorization_code_flow(client, oauth_client):
    """Fluxo Authorization Code completo: registro → login → authorize → token
    → rota protegida → refresh → revogação → confirmação cascade."""

    # ── 1. Registrar usuário ────────────────────────────────────────────────
    reg = await client.post(
        "/auth/register",
        json={
            "name": "E2E User",
            "email": "e2e@example.com",
            "password": "Senha1234",
        },
    )
    assert reg.status_code == 201

    # ── 2. Login (obtém token interno para usar em /oauth/authorize) ────────
    login = await client.post(
        "/auth/login",
        json={"email": "e2e@example.com", "password": "Senha1234"},
    )
    assert login.status_code == 200
    login_token = login.json()["access_token"]

    # ── 3. Authorization Code Flow — GET /oauth/authorize ───────────────────
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    authorize = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "e2e_state",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        headers={"Authorization": f"Bearer {login_token}"},
        follow_redirects=False,
    )
    assert authorize.status_code == 302
    location = authorize.headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

    # ── 4. Token Exchange — POST /oauth/token ────────────────────────────────
    exchange = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code_verifier": code_verifier,
        },
    )
    assert exchange.status_code == 200
    access_token_1 = exchange.json()["access_token"]
    refresh_token_1 = exchange.json()["refresh_token"]

    # ── 5. Acessar rota protegida ────────────────────────────────────────────
    me = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {access_token_1}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == "e2e@example.com"

    # ── 6. Refresh token → novo par de tokens ───────────────────────────────
    refresh = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_1,
            "client_id": "test_client",
            "client_secret": "test_secret",
        },
    )
    assert refresh.status_code == 200
    access_token_2 = refresh.json()["access_token"]
    refresh_token_2 = refresh.json()["refresh_token"]

    # ── 7. Revogar refresh_token_2 ───────────────────────────────────────────
    revoke_resp = await client.post(
        "/oauth/revoke",
        data={
            "token": refresh_token_2,
            "client_id": "test_client",
            "client_secret": "test_secret",
        },
    )
    assert revoke_resp.status_code == 200

    # ── 8. access_token_2 (derivado de refresh_token_2) deve estar inválido ─
    me_after = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {access_token_2}"}
    )
    assert me_after.status_code == 401

    # ── 9. refresh_token_2 revogado → POST /oauth/token deve falhar ──────────
    retry_refresh = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_2,
            "client_id": "test_client",
            "client_secret": "test_secret",
        },
    )
    assert retry_refresh.status_code == 400
