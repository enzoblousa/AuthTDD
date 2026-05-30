"""Schemas Pydantic para autenticação via login (M2) e dados de token (M6)."""

from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Dados extraídos do JWT após validação (M6)."""

    sub: str
    scopes: list[str] = []
    jti: str
    exp: int
