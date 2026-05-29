"""Testes unitários do service de autenticação e da validação de senha (M1+M2).

Mapeia U1–U6 de `specs/01_user_registration.md` e
U7–U9 de `specs/02_login.md`.
"""

import pytest
from pydantic import ValidationError

from app.core.security import hash_password, verify_password
from app.models.user import User
from app.schemas.user import UserRegisterRequest
from app.services.auth_service import authenticate_user, create_user


# --- U1 / U2: senha hasheada antes de salvar, e verificável ---------------


async def test_create_user_stores_hashed_password(db_session):
    payload = UserRegisterRequest(
        name="João Silva", email="joao@exemplo.com", password="Senha1234"
    )

    user = await create_user(db_session, payload)

    assert user.hashed_password != "Senha1234"
    assert verify_password("Senha1234", user.hashed_password) is True


# --- U3: senha muito curta ------------------------------------------------


def test_password_too_short_raises():
    with pytest.raises(ValidationError):
        UserRegisterRequest(name="João Silva", email="joao@exemplo.com", password="Ab1")


# --- U4: senha sem letra maiúscula ----------------------------------------


def test_password_without_uppercase_raises():
    with pytest.raises(ValidationError):
        UserRegisterRequest(
            name="João Silva", email="joao@exemplo.com", password="senha1234"
        )


# --- U5: senha sem número -------------------------------------------------


def test_password_without_number_raises():
    with pytest.raises(ValidationError):
        UserRegisterRequest(
            name="João Silva", email="joao@exemplo.com", password="SenhaForte"
        )


# --- U6: senha válida -----------------------------------------------------


def test_valid_password_is_accepted():
    req = UserRegisterRequest(
        name="João Silva", email="joao@exemplo.com", password="Senha1234"
    )
    assert req.password == "Senha1234"


def test_password_without_lowercase_raises():
    with pytest.raises(ValidationError):
        UserRegisterRequest(
            name="João Silva", email="joao@exemplo.com", password="SENHA1234"
        )


# --- U7: autenticação com senha correta retorna User (M2) -----------------


async def test_authenticate_user_with_correct_password_returns_user(db_session):
    user = User(
        name="João Silva",
        email="joao@exemplo.com",
        hashed_password=hash_password("Senha1234"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    result = await authenticate_user(db_session, "joao@exemplo.com", "Senha1234")

    assert result is not None
    assert result.email == "joao@exemplo.com"


# --- U8: autenticação com senha errada retorna None -----------------------


async def test_authenticate_user_with_wrong_password_returns_none(db_session):
    user = User(
        name="João Silva",
        email="joao@exemplo.com",
        hashed_password=hash_password("Senha1234"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    result = await authenticate_user(db_session, "joao@exemplo.com", "SenhaErrada9")

    assert result is None


# --- U9: autenticação com e-mail inexistente retorna None -----------------


async def test_authenticate_user_with_nonexistent_email_returns_none(db_session):
    result = await authenticate_user(db_session, "naoexiste@exemplo.com", "Senha1234")

    assert result is None
