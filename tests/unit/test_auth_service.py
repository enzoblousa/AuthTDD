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


# =============================================================================
# M6 — Rotas protegidas: get_current_user_from_token + require_scope (U1–U6)
# =============================================================================

from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.core.security import hash_password
from app.models.user import User
from app.services.auth_service import get_current_user_from_token
from app.services.token_service import create_access_token


# --- M6·U1: token válido retorna o user correto -----------------------------


async def test_valid_token_returns_correct_user(db_session):
    """M6·U1: JWT válido → objeto User com o sub correto."""
    user = User(
        name="Protected User",
        email="protected@example.com",
        hashed_password=hash_password("Senha1234"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token({"sub": str(user.id), "scope": "openid profile"})
    result = await get_current_user_from_token(token, db_session)
    assert result.id == user.id


# --- M6·U2: token expirado lança 401 ----------------------------------------


async def test_expired_token_raises_401(db_session):
    """M6·U2: JWT com exp no passado → HTTPException 401."""
    token = create_access_token(
        {"sub": "any-id", "scope": "openid"},
        expires_delta=timedelta(seconds=-1),
    )
    with pytest.raises(HTTPException) as exc:
        await get_current_user_from_token(token, db_session)
    assert exc.value.status_code == 401


# --- M6·U3: token com assinatura inválida lança 401 -------------------------


async def test_tampered_token_raises_401(db_session):
    """M6·U3: JWT adulterado → HTTPException 401."""
    token = create_access_token({"sub": "any-id", "scope": "openid"})
    tampered = token[:-1] + ("X" if token[-1] != "X" else "Y")
    with pytest.raises(HTTPException) as exc:
        await get_current_user_from_token(tampered, db_session)
    assert exc.value.status_code == 401


# --- M6·U4: usuário inativo lança 401 ----------------------------------------


async def test_inactive_user_raises_401(db_session):
    """M6·U4: is_active=False → HTTPException 401."""
    inactive = User(
        name="Inactive",
        email="inactive@example.com",
        hashed_password=hash_password("Senha1234"),
        is_active=False,
    )
    db_session.add(inactive)
    await db_session.commit()
    await db_session.refresh(inactive)

    token = create_access_token({"sub": str(inactive.id), "scope": "openid"})
    with pytest.raises(HTTPException) as exc:
        await get_current_user_from_token(token, db_session)
    assert exc.value.status_code == 401


# --- M6·U5: require_scope com scope presente não lança ----------------------


async def test_require_scope_passes_when_scope_present():
    """M6·U5: scope presente → sem exceção."""
    from app.core.dependencies import require_scope
    from app.schemas.token import TokenData

    token_data = TokenData(
        sub="uid", scopes=["openid", "profile"], jti="test-jti", exp=9_999_999_999
    )
    checker = require_scope("profile")
    await checker(token_data)  # deve passar sem exceção


# --- M6·U6: require_scope com scope ausente lança 403 -----------------------


async def test_require_scope_raises_403_when_scope_missing():
    """M6·U6: scope ausente → HTTPException 403."""
    from app.core.dependencies import require_scope
    from app.schemas.token import TokenData

    token_data = TokenData(
        sub="uid", scopes=["openid"], jti="test-jti", exp=9_999_999_999
    )
    checker = require_scope("profile")
    with pytest.raises(HTTPException) as exc:
        await checker(token_data)
    assert exc.value.status_code == 403
