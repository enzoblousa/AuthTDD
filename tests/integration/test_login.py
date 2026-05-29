"""Testes de integração do endpoint POST /auth/login (M2).

Mapeia os casos I1–I10 da spec `specs/02_login.md`.
"""

from jose import jwt

from app.config import settings

VALID_PAYLOAD = {"email": "test@example.com", "password": "Senha1234"}


# --- I1: login com credenciais válidas → 200 com access_token -------------


async def test_login_with_valid_credentials_returns_200(client, test_user):
    response = await client.post("/auth/login", json=VALID_PAYLOAD)

    assert response.status_code == 200
    assert "access_token" in response.json()


# --- I2: token retornado é JWT decodificável ------------------------------


async def test_login_token_is_valid_jwt(client, test_user):
    response = await client.post("/auth/login", json=VALID_PAYLOAD)

    token = response.json()["access_token"]
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

    assert "sub" in payload
    assert "exp" in payload


# --- I3: claims do token estão corretos -----------------------------------


async def test_login_token_has_correct_claims(client, test_user):
    response = await client.post("/auth/login", json=VALID_PAYLOAD)

    token = response.json()["access_token"]
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

    assert payload["sub"] == str(test_user.id)
    assert payload["email"] == test_user.email


# --- I4: token_type é "bearer" --------------------------------------------


async def test_login_returns_bearer_token_type(client, test_user):
    response = await client.post("/auth/login", json=VALID_PAYLOAD)

    assert response.json()["token_type"] == "bearer"


# --- I5: senha errada → 401 -----------------------------------------------


async def test_login_with_wrong_password_returns_401(client, test_user):
    payload = {**VALID_PAYLOAD, "password": "SenhaErrada9"}
    response = await client.post("/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


# --- I6: e-mail inexistente → 401 -----------------------------------------


async def test_login_with_nonexistent_email_returns_401(client):
    payload = {"email": "naoexiste@exemplo.com", "password": "Senha1234"}
    response = await client.post("/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


# --- I7: mensagem de erro idêntica para senha errada e e-mail inexistente -


async def test_login_error_message_is_identical_for_wrong_password_and_unknown_email(
    client, test_user
):
    wrong_password = await client.post(
        "/auth/login", json={**VALID_PAYLOAD, "password": "SenhaErrada9"}
    )
    unknown_email = await client.post(
        "/auth/login", json={"email": "naoexiste@exemplo.com", "password": "Senha1234"}
    )

    assert wrong_password.json()["detail"] == unknown_email.json()["detail"]


# --- I8: usuário inativo não pode logar → 401 -----------------------------


async def test_login_with_inactive_user_returns_401(client, db_session):
    from app.core.security import hash_password
    from app.models.user import User

    inactive = User(
        name="Inativo",
        email="inativo@example.com",
        hashed_password=hash_password("Senha1234"),
        is_active=False,
    )
    db_session.add(inactive)
    await db_session.commit()

    response = await client.post(
        "/auth/login", json={"email": "inativo@example.com", "password": "Senha1234"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


# --- I9: body vazio → 422 -------------------------------------------------


async def test_login_with_empty_body_returns_422(client):
    response = await client.post("/auth/login", json={})
    assert response.status_code == 422


# --- I10: campo password ausente → 422 ------------------------------------


async def test_login_without_password_returns_422(client):
    response = await client.post("/auth/login", json={"email": "test@example.com"})
    assert response.status_code == 422
