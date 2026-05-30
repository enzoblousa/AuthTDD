"""Exceções customizadas da aplicação."""


class OAuthError(Exception):
    """Erro do protocolo OAuth2 (RFC 6749 §5.2)."""

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)
