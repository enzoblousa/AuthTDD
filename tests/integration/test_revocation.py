"""Testes de integração do endpoint POST /oauth/revoke (M7).

Mapeia I1–I10 de specs/07_revocation.md.
"""


def _revoke(token_pair: dict, overrides: dict | None = None) -> dict:
    base = {
        "token": token_pair["access_token"],
        "client_id": token_pair["client_id"],
        "client_secret": token_pair["client_secret"],
    }
    if overrides:
        base.update(overrides)
    return base


# --- I1 -------------------------------------------------------------------


async def test_revoke_access_token_returns_200(client, token_pair):
    """I1: revogar access token → 200 {}."""
    response = await client.post("/oauth/revoke", data=_revoke(token_pair))
    assert response.status_code == 200
    assert response.json() == {}


# --- I2 -------------------------------------------------------------------


async def test_revoked_access_token_cannot_access_protected_route(client, token_pair):
    """I2: access token revogado → 401 em GET /users/me."""
    await client.post("/oauth/revoke", data=_revoke(token_pair))
    response = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token_pair['access_token']}"},
    )
    assert response.status_code == 401


# --- I3 -------------------------------------------------------------------


async def test_revoke_refresh_token_returns_200(client, token_pair):
    """I3: revogar refresh token → 200 {}."""
    response = await client.post(
        "/oauth/revoke",
        data=_revoke(token_pair, {"token": token_pair["refresh_token"]}),
    )
    assert response.status_code == 200
    assert response.json() == {}


# --- I4 -------------------------------------------------------------------


async def test_revoked_refresh_token_cannot_be_used(client, token_pair):
    """I4: refresh token revogado → 400 em POST /oauth/token."""
    await client.post(
        "/oauth/revoke",
        data=_revoke(token_pair, {"token": token_pair["refresh_token"]}),
    )
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["refresh_token"],
            "client_id": token_pair["client_id"],
            "client_secret": token_pair["client_secret"],
        },
    )
    assert response.status_code == 400


# --- I5 -------------------------------------------------------------------


async def test_revoking_refresh_token_invalidates_derived_access_token(client, token_pair):
    """I5: revogar refresh token invalida o access token associado → 401 em /users/me."""
    await client.post(
        "/oauth/revoke",
        data=_revoke(token_pair, {"token": token_pair["refresh_token"]}),
    )
    response = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token_pair['access_token']}"},
    )
    assert response.status_code == 401


# --- I6 -------------------------------------------------------------------


async def test_revoke_nonexistent_token_returns_200(client, token_pair):
    """I6: token inexistente → 200 {} (RFC 7009 não revela existência)."""
    response = await client.post(
        "/oauth/revoke",
        data=_revoke(token_pair, {"token": "token-que-nao-existe-absolutamente"}),
    )
    assert response.status_code == 200
    assert response.json() == {}


# --- I7 -------------------------------------------------------------------


async def test_revoke_other_client_token_returns_200_without_revoking(
    client, token_pair, db_session
):
    """I7: token de outro client → 200 sem revogar (RFC 7009)."""
    import json

    from app.models.oauth_client import OAuthClient

    second = OAuthClient(
        client_id="second_client_revoke",
        client_secret="second_secret_revoke",
        name="Second",
        redirect_uris=json.dumps(["http://localhost/cb"]),
        scopes="openid profile",
        is_active=True,
    )
    db_session.add(second)
    await db_session.commit()

    # Tenta revogar o refresh_token do test_client usando credenciais do second_client
    response = await client.post(
        "/oauth/revoke",
        data={
            "token": token_pair["refresh_token"],
            "client_id": "second_client_revoke",
            "client_secret": "second_secret_revoke",
        },
    )
    assert response.status_code == 200

    # O refresh token do test_client ainda deve funcionar
    use_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["refresh_token"],
            "client_id": token_pair["client_id"],
            "client_secret": token_pair["client_secret"],
        },
    )
    assert use_response.status_code == 200


# --- I8 -------------------------------------------------------------------


async def test_invalid_client_secret_returns_401(client, token_pair):
    """I8: client_secret errado → 401 invalid_client."""
    response = await client.post(
        "/oauth/revoke",
        data=_revoke(token_pair, {"client_secret": "wrong_secret"}),
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


# --- I9 -------------------------------------------------------------------


async def test_revoke_without_hint_works_correctly(client, token_pair):
    """I9: sem token_type_hint → funciona corretamente (revoga access token)."""
    form = {
        "token": token_pair["access_token"],
        "client_id": token_pair["client_id"],
        "client_secret": token_pair["client_secret"],
    }
    response = await client.post("/oauth/revoke", data=form)
    assert response.status_code == 200

    me = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token_pair['access_token']}"},
    )
    assert me.status_code == 401


# --- I10 ------------------------------------------------------------------


async def test_wrong_hint_still_revokes_correctly(client, token_pair):
    """I10: hint='access_token' mas token é refresh → sistema tenta ambos e revoga."""
    response = await client.post(
        "/oauth/revoke",
        data=_revoke(
            token_pair,
            {
                "token": token_pair["refresh_token"],
                "token_type_hint": "access_token",
            },
        ),
    )
    assert response.status_code == 200

    # O refresh token deve ter sido revogado mesmo com hint errado
    use_response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["refresh_token"],
            "client_id": token_pair["client_id"],
            "client_secret": token_pair["client_secret"],
        },
    )
    assert use_response.status_code == 400
