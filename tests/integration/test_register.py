"""Testes de integração do endpoint POST /auth/register (M1).

Mapeia os casos I1–I11 da spec `specs/01_user_registration.md`.
"""

VALID_PAYLOAD = {
    "name": "João Silva",
    "email": "joao@exemplo.com",
    "password": "Senha1234",
}


# --- I1: registro com dados válidos → 201 ---------------------------------


async def test_register_with_valid_data_returns_201(client):
    response = await client.post("/auth/register", json=VALID_PAYLOAD)

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == VALID_PAYLOAD["email"]
    assert data["name"] == VALID_PAYLOAD["name"]
    assert "id" in data
    assert "created_at" in data


# --- I2: resposta não contém senha ----------------------------------------


async def test_register_response_does_not_contain_password(client):
    response = await client.post("/auth/register", json=VALID_PAYLOAD)

    data = response.json()
    assert "password" not in data
    assert "hashed_password" not in data


# --- I3: e-mail duplicado → 400 -------------------------------------------


async def test_register_with_duplicate_email_returns_400(client):
    first = await client.post("/auth/register", json=VALID_PAYLOAD)
    assert first.status_code == 201

    second = await client.post("/auth/register", json=VALID_PAYLOAD)
    assert second.status_code == 400
    assert second.json()["detail"] == "Email already registered"


# --- I4: e-mail inválido → 422 --------------------------------------------


async def test_register_with_invalid_email_returns_422(client):
    payload = {**VALID_PAYLOAD, "email": "nao-e-email"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I5: senha muito curta → 422 ------------------------------------------


async def test_register_with_short_password_returns_422(client):
    payload = {**VALID_PAYLOAD, "password": "Ab1"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I6: senha sem maiúscula → 422 ----------------------------------------


async def test_register_with_password_without_uppercase_returns_422(client):
    payload = {**VALID_PAYLOAD, "password": "senha1234"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I7: senha sem número → 422 -------------------------------------------


async def test_register_with_password_without_number_returns_422(client):
    payload = {**VALID_PAYLOAD, "password": "SenhaForte"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I8: nome ausente → 422 -----------------------------------------------


async def test_register_without_name_returns_422(client):
    payload = {"email": "joao@exemplo.com", "password": "Senha1234"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I9: nome muito curto → 422 -------------------------------------------


async def test_register_with_short_name_returns_422(client):
    payload = {**VALID_PAYLOAD, "name": "A"}
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- I10: body vazio → 422 ------------------------------------------------


async def test_register_with_empty_body_returns_422(client):
    response = await client.post("/auth/register", json={})
    assert response.status_code == 422


# --- I11: usuário criado com is_active=True -------------------------------


async def test_register_creates_active_user(client):
    response = await client.post("/auth/register", json=VALID_PAYLOAD)
    assert response.status_code == 201
    assert response.json()["is_active"] is True
