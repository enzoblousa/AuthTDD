"""Modelo ORM de cliente OAuth2."""

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    client_id: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )
    client_secret: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[str] = mapped_column(String(500), nullable=False, default="openid")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    def get_redirect_uris(self) -> list[str]:
        return json.loads(self.redirect_uris)

    def get_scopes(self) -> list[str]:
        return self.scopes.split()
