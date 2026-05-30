"""Endpoints de usuário — rotas protegidas (M6)."""

from fastapi import APIRouter, Depends

from app.core.dependencies import get_current_user, get_token_data, require_scope
from app.models.user import User
from app.schemas.token import TokenData
from app.schemas.user import UserProfileResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserProfileResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
    token_data: TokenData = Depends(get_token_data),
    _: None = Depends(require_scope("profile")),
) -> UserProfileResponse:
    """Retorna o perfil do usuário autenticado com os scopes do token (M6)."""
    return UserProfileResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        is_active=current_user.is_active,
        scopes=token_data.scopes,
        created_at=current_user.created_at,
    )
