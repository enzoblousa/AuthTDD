"""FastAPI dependencies — autenticação JWT, blacklist e scopes (M6)."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.token import RevokedToken
from app.models.user import User
from app.schemas.token import TokenData
from app.services.auth_service import get_current_user_from_token, get_user_by_id
from app.services.token_service import decode_access_token

# auto_error=False → retornamos 401 manualmente (padrão seria 403)
_bearer = HTTPBearer(auto_error=False)


async def get_token_data(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> TokenData:
    """Extrai e valida o JWT; verifica blacklist; devolve TokenData com scopes."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str | None = payload.get("sub")
        jti: str | None = payload.get("jti")
        scope_str: str = payload.get("scope", "")
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

    return TokenData(
        sub=user_id,
        scopes=scope_str.split() if scope_str else [],
        jti=jti,
        exp=payload.get("exp", 0),
    )


async def get_current_user(
    token_data: TokenData = Depends(get_token_data),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Retorna o User ativo associado ao token."""
    user = await get_user_by_id(db, token_data.sub)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user


def require_scope(*required_scopes: str):
    """Factory de dependência para verificação de scopes (spec M6 regra 5)."""

    async def check_scope(token_data: TokenData = Depends(get_token_data)) -> None:
        for scope in required_scopes:
            if scope not in token_data.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient scope. Required: {scope}",
                )

    return check_scope
