"""Testes unitários do serviço OAuth2 (M3: authorization code).

Mapeia U1–U4 de specs/03_oauth_authorize.md.
"""

from datetime import datetime, timedelta, timezone

from app.services.oauth_service import generate_authorization_code

_PARAMS = dict(
    client_id="test_client",
    user_id="user-id-123",
    redirect_uri="http://localhost:3000/callback",
    scope="openid",
    state=None,
    code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method="S256",
)


async def test_generated_code_has_sufficient_entropy(db_session):
    """U1: len(code) >= 43 chars (32 bytes em base64url = 43 chars sem padding)."""
    auth_code = await generate_authorization_code(db=db_session, **_PARAMS)
    assert len(auth_code.code) >= 43


async def test_two_generated_codes_are_different(db_session):
    """U2: dois códigos gerados são distintos."""
    code_a = await generate_authorization_code(db=db_session, **_PARAMS)
    code_b = await generate_authorization_code(db=db_session, **_PARAMS)
    assert code_a.code != code_b.code


async def test_code_expires_in_10_minutes(db_session):
    """U3: expires_at está dentro da janela now+10min (±1s de margem)."""
    before = datetime.now(timezone.utc)
    auth_code = await generate_authorization_code(db=db_session, **_PARAMS)
    after = datetime.now(timezone.utc)

    expires = auth_code.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    assert before + timedelta(minutes=10) <= expires <= after + timedelta(minutes=10)


async def test_code_created_with_used_false(db_session):
    """U4: código recém-criado tem used == False."""
    auth_code = await generate_authorization_code(db=db_session, **_PARAMS)
    assert auth_code.used is False
