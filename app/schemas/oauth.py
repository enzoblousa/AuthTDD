"""Schemas Pydantic para o fluxo OAuth2 (M3+)."""

from typing import Literal

from pydantic import BaseModel, HttpUrl


class AuthorizeRequest(BaseModel):
    response_type: Literal["code"]
    client_id: str
    redirect_uri: HttpUrl
    scope: str = "openid"
    state: str | None = None
    code_challenge: str
    code_challenge_method: Literal["S256"]


class TokenRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: HttpUrl
    client_id: str
    client_secret: str
    code_verifier: str


class OAuthTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    client_id: str
    client_secret: str


class RevokeRequest(BaseModel):
    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str
    client_secret: str
