"""Fixtures globais para os testes.

Estratégia de banco: SQLite **em memória** com `StaticPool`, garantindo que
todas as sessões compartilhem a mesma conexão (necessário para `:memory:`).
As tabelas são criadas no início de cada teste e descartadas no fim, dando
isolamento total entre testes.
"""

import base64
import hashlib
import secrets
from collections.abc import AsyncGenerator
from urllib.parse import parse_qs, urlparse

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Sessão de banco isolada, sobre um SQLite em memória."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Importa os modelos para que fiquem registrados no metadata antes do create_all.
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    async with session_maker() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Cliente HTTP assíncrono com a dependência de banco sobrescrita."""

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def oauth_client(db_session: AsyncSession):
    """Cliente OAuth2 cadastrado no banco para testes de M3+."""
    import json

    from app.models.oauth_client import OAuthClient

    record = OAuthClient(
        client_id="test_client",
        client_secret="test_secret",
        name="Test App",
        redirect_uris=json.dumps(["http://localhost:3000/callback"]),
        scopes="openid profile email",
        is_active=True,
    )
    db_session.add(record)
    await db_session.commit()
    await db_session.refresh(record)
    return record


@pytest_asyncio.fixture
async def authenticated_user(client: AsyncClient, test_user):
    """Usuário já registrado e com JWT válido (senha: 'Senha1234')."""
    response = await client.post(
        "/auth/login",
        json={"email": "test@example.com", "password": "Senha1234"},
    )
    token = response.json()["access_token"]
    return {"user": test_user, "token": token}


@pytest_asyncio.fixture
async def authorization_code_data(client: AsyncClient, oauth_client, authenticated_user):
    """Executa GET /oauth/authorize e devolve code + verifier para testes de M4+."""
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    params = {
        "response_type": "code",
        "client_id": "test_client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "openid profile",
        "state": "test_state",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    response = await client.get(
        "/oauth/authorize",
        params=params,
        headers={"Authorization": f"Bearer {authenticated_user['token']}"},
        follow_redirects=False,
    )
    location = response.headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

    return {
        "code": code,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": "test_client",
        "client_secret": "test_secret",
        "scope": "openid profile",
    }


@pytest_asyncio.fixture
async def token_pair(client: AsyncClient, authorization_code_data):
    """Executa POST /oauth/token e devolve (access_token, refresh_token) para M7."""
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_data["code"],
            "redirect_uri": authorization_code_data["redirect_uri"],
            "client_id": authorization_code_data["client_id"],
            "client_secret": authorization_code_data["client_secret"],
            "code_verifier": authorization_code_data["code_verifier"],
        },
    )
    body = response.json()
    return {
        "access_token": body["access_token"],
        "refresh_token": body["refresh_token"],
        "client_id": authorization_code_data["client_id"],
        "client_secret": authorization_code_data["client_secret"],
    }


@pytest_asyncio.fixture
async def valid_refresh_token(client: AsyncClient, authorization_code_data):
    """Executa POST /oauth/token (M4) e devolve os dados do refresh token para M5."""
    response = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization_code_data["code"],
            "redirect_uri": authorization_code_data["redirect_uri"],
            "client_id": authorization_code_data["client_id"],
            "client_secret": authorization_code_data["client_secret"],
            "code_verifier": authorization_code_data["code_verifier"],
        },
    )
    body = response.json()
    return {
        "refresh_token": body["refresh_token"],
        "client_id": authorization_code_data["client_id"],
        "client_secret": authorization_code_data["client_secret"],
        "scope": authorization_code_data["scope"],
    }


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession):
    """Usuário já registrado no banco (senha: 'Senha1234').

    Importes locais para não acoplar a coleta dos testes à existência dos
    módulos de produção antes de eles serem implementados (disciplina TDD).
    """
    from app.core.security import hash_password
    from app.models.user import User

    user = User(
        name="Test User",
        email="test@example.com",
        hashed_password=hash_password("Senha1234"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
