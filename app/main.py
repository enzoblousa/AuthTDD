"""Entry point da aplicação FastAPI."""

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base, engine, get_db
from app.models import AuthorizationCode, OAuthClient, RefreshToken, RevokedToken, User  # noqa: F401
from app.routers import auth, oauth, users


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="auth-tdd",
    description="Sistema de Autenticação OAuth2 — SDD + TDD",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(users.router)

_HTML = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root() -> str:
    return _HTML


@app.get("/demo/callback", include_in_schema=False)
async def demo_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> JSONResponse:
    """Captura o redirect do Authorization Code Flow e devolve JSON ao cliente demo."""
    if error:
        return JSONResponse({"error": error, "state": state})
    return JSONResponse({"code": code, "state": state})


@app.post("/demo/setup", tags=["demo"])
async def demo_setup(db: AsyncSession = Depends(get_db)) -> dict:
    """Cria (ou retorna) o cliente OAuth2 de demonstração."""
    result = await db.execute(
        select(OAuthClient).where(OAuthClient.client_id == "demo-client")
    )
    existing = result.scalar_one_or_none()
    redirect_uri = "http://localhost:8000/demo/callback"

    if existing:
        return {
            "client_id": "demo-client",
            "client_secret": "demo-secret-2024",
            "redirect_uri": redirect_uri,
            "scopes": existing.scopes,
            "status": "already_exists",
        }

    client = OAuthClient(
        client_id="demo-client",
        client_secret="demo-secret-2024",
        name="Demo Application",
        redirect_uris=json.dumps([redirect_uri]),
        scopes="openid profile email",
        is_active=True,
    )
    db.add(client)
    await db.commit()

    return {
        "client_id": "demo-client",
        "client_secret": "demo-secret-2024",
        "redirect_uri": redirect_uri,
        "scopes": "openid profile email",
        "status": "created",
    }


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Health check simples."""
    return {"status": "ok"}
