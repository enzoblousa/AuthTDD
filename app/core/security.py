"""Utilitários de segurança: hashing de senha, PKCE."""

import base64
import hashlib
import secrets

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Gera um hash bcrypt da senha. Nunca retorna o texto plano."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha em texto plano corresponde ao hash armazenado."""
    return pwd_context.verify(plain_password, hashed_password)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verifica PKCE S256: sha256(code_verifier) base64url == code_challenge.

    Usa compare_digest para proteção contra timing attacks (spec M4 §5).
    """
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, code_challenge)
