"""Reexporta os modelos para que fiquem registrados no metadata do SQLAlchemy."""

from app.models.oauth_client import OAuthClient
from app.models.token import AuthorizationCode, RefreshToken, RevokedToken
from app.models.user import User

__all__ = ["User", "OAuthClient", "AuthorizationCode", "RefreshToken", "RevokedToken"]
