"""Entry point da aplicação FastAPI."""

from fastapi import FastAPI

from app.routers import auth

app = FastAPI(
    title="auth-tdd",
    description="Sistema de Autenticação OAuth2 — SDD + TDD",
    version="0.1.0",
)

app.include_router(auth.router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Health check simples."""
    return {"status": "ok"}
