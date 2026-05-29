"""Reexporta os modelos para que fiquem registrados no metadata do SQLAlchemy."""

from app.models.user import User

__all__ = ["User"]
