"""Lógica de negócio de autenticação (M1: registro, M2: login, M6: token validation)."""

from fastapi import HTTPException, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models.token import RevokedToken
from app.models.user import User
from app.schemas.user import UserRegisterRequest
from app.services.token_service import decode_access_token

# Hash sentinela pré-computado — usado quando o e-mail não existe para que o
# tempo de resposta seja igual ao caminho "senha errada" (proteção anti-timing).
_DUMMY_HASH: str = hash_password("guard-dummy-never-matches-any-real-password")


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Retorna o usuário com o e-mail informado, ou None."""
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    """Retorna o usuário com o ID informado, ou None."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_current_user_from_token(token_str: str, db: AsyncSession) -> User:
    """Valida JWT, verifica blacklist e retorna o User ativo.

    Função pura (sem dependência FastAPI) — testável diretamente (M6 U1-U4).
    """
    try:
        payload = decode_access_token(token_str)
        user_id: str | None = payload.get("sub")
        jti: str | None = payload.get("jti")
        if not user_id or not jti:
            raise ValueError("Missing required claims")
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    revoked = await db.execute(select(RevokedToken).where(RevokedToken.jti == jti))
    if revoked.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user = await get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    """Verifica credenciais e retorna o User ativo, ou None.

    Sempre executa verify_password (caminho de tempo constante) para evitar
    timing attacks por enumeração de e-mails (spec M2 regra 6).
    """
    user = await get_user_by_email(db, email)
    reference_hash = user.hashed_password if user else _DUMMY_HASH
    password_ok = verify_password(password, reference_hash)

    if not password_ok or user is None or not user.is_active:
        return None
    return user


async def create_user(db: AsyncSession, payload: UserRegisterRequest) -> User:
    """Cria e persiste um novo usuário com a senha já hasheada."""
    user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
