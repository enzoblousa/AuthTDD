"""Lógica de negócio do fluxo OAuth2 (M3+)."""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import OAuthError
from app.core.security import verify_pkce
from app.models.oauth_client import OAuthClient
from app.models.token import AuthorizationCode, RefreshToken, RevokedToken
from app.services.token_service import create_access_token, decode_token_claims


async def generate_authorization_code(
    db: AsyncSession,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scope: str,
    state: str | None,
    code_challenge: str,
    code_challenge_method: str,
) -> AuthorizationCode:
    """Gera, persiste e retorna um authorization code de uso único."""
    code = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.auth_code_expire_minutes
    )
    auth_code = AuthorizationCode(
        code=code,
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=expires_at,
        used=False,
    )
    db.add(auth_code)
    await db.commit()
    await db.refresh(auth_code)
    return auth_code


async def validate_authorize_request(
    db: AsyncSession,
    client_id: str,
    redirect_uri: str,
) -> OAuthClient:
    """Valida client_id e redirect_uri. Lança HTTPException 400 se inválido.

    Nunca redireciona para URIs não confiáveis (spec M3 regra de negócio 2).
    """
    result = await db.execute(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id, OAuthClient.is_active == True  # noqa: E712
        )
    )
    client = result.scalar_one_or_none()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id or redirect_uri",
        )

    normalized_uri = redirect_uri.rstrip("/")
    registered = [u.rstrip("/") for u in client.get_redirect_uris()]
    if normalized_uri not in registered:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id or redirect_uri",
        )

    return client


async def generate_refresh_token(
    db: AsyncSession,
    user_id: str,
    client_id: str,
    scope: str,
    access_token_jti: str | None = None,
) -> RefreshToken:
    """Gera, persiste e retorna um refresh token opaco (não-JWT).

    `access_token_jti` armazena o jti do access token emitido junto — necessário
    para revogação em cascata (spec M7 regra 4).
    """
    token_value = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )
    rt = RefreshToken(
        token=token_value,
        user_id=user_id,
        client_id=client_id,
        scope=scope,
        expires_at=expires_at,
        revoked=False,
        access_token_jti=access_token_jti,
    )
    db.add(rt)
    await db.commit()
    await db.refresh(rt)
    return rt


async def exchange_code_for_tokens(
    db: AsyncSession,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
) -> tuple[str, RefreshToken]:
    """Troca o authorization code por access + refresh token.

    Valida PKCE, client, expiração e uso único (spec M4 regras 1-8).
    Lança OAuthError em qualquer falha de validação.
    """
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(AuthorizationCode).where(AuthorizationCode.code == code)
    )
    auth_code = result.scalar_one_or_none()
    if auth_code is None:
        raise OAuthError("invalid_grant", "Authorization code not found")

    expires = auth_code.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        raise OAuthError("invalid_grant", "Authorization code has expired")

    if auth_code.used:
        raise OAuthError("invalid_grant", "Authorization code has already been used")

    client_result = await db.execute(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.is_active == True,  # noqa: E712
        )
    )
    oauth_client = client_result.scalar_one_or_none()
    if oauth_client is None:
        raise OAuthError("invalid_client", "Client not found")
    if not secrets.compare_digest(client_secret, oauth_client.client_secret):
        raise OAuthError("invalid_client", "Invalid client credentials")

    if auth_code.client_id != client_id:
        raise OAuthError("invalid_grant", "Client mismatch")

    if redirect_uri.rstrip("/") != auth_code.redirect_uri.rstrip("/"):
        raise OAuthError("invalid_grant", "redirect_uri mismatch")

    if not verify_pkce(code_verifier, auth_code.code_challenge):
        raise OAuthError("invalid_grant", "PKCE verification failed")

    # Marca o código como usado (one-time use — spec M4 regra 6)
    auth_code.used = True
    await db.commit()

    access_token = create_access_token({"sub": auth_code.user_id, "scope": auth_code.scope})
    at_jti = decode_token_claims(access_token).get("jti")
    rt = await generate_refresh_token(
        db=db,
        user_id=auth_code.user_id,
        client_id=client_id,
        scope=auth_code.scope,
        access_token_jti=at_jti,
    )
    return access_token, rt


async def rotate_refresh_token(
    db: AsyncSession,
    old_rt: RefreshToken,
    access_token_jti: str | None = None,
) -> RefreshToken:
    """Cria novo refresh token, revoga o antigo e registra o link de auditoria.

    O novo token herda scope e expires_at do original (spec M5 regras 4 e 7).
    `access_token_jti` vincula o novo access token ao novo refresh token (M7 cascade).
    """
    new_rt = RefreshToken(
        token=secrets.token_urlsafe(32),
        user_id=old_rt.user_id,
        client_id=old_rt.client_id,
        scope=old_rt.scope,
        expires_at=old_rt.expires_at,
        revoked=False,
        access_token_jti=access_token_jti,
    )
    db.add(new_rt)
    await db.flush()  # atribui new_rt.id antes do link de auditoria

    old_rt.revoked = True
    old_rt.revoked_at = datetime.now(timezone.utc)
    old_rt.replaced_by = new_rt.id

    await db.commit()
    await db.refresh(new_rt)
    return new_rt


async def handle_refresh_token_reuse(
    db: AsyncSession, user_id: str, client_id: str
) -> None:
    """Revoga TODOS os refresh tokens ativos do par user+client.

    Acionado quando um token já revogado é apresentado novamente — possível
    roubo de token (spec M5 regra 5).
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.client_id == client_id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    for rt in result.scalars().all():
        rt.revoked = True
        rt.revoked_at = now
    await db.commit()


async def refresh_token_grant(
    db: AsyncSession,
    refresh_token_str: str,
    client_id: str,
    client_secret: str,
) -> tuple[str, RefreshToken]:
    """Processa o grant_type=refresh_token com rotação e detecção de roubo.

    Lança OAuthError em qualquer falha de validação (spec M5 regras 1-7).
    """
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token == refresh_token_str)
    )
    rt = result.scalar_one_or_none()
    if rt is None:
        raise OAuthError("invalid_grant", "Refresh token not found")

    # Detecção de roubo: token revogado apresentado novamente (spec M5 regra 5)
    if rt.revoked:
        await handle_refresh_token_reuse(db, rt.user_id, rt.client_id)
        raise OAuthError("invalid_grant", "Refresh token has been revoked")

    expires = rt.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        raise OAuthError("invalid_grant", "Refresh token has expired")

    # Autentica o client
    client_result = await db.execute(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.is_active == True,  # noqa: E712
        )
    )
    oauth_client = client_result.scalar_one_or_none()
    if oauth_client is None:
        raise OAuthError("invalid_client", "Client not found")
    if not secrets.compare_digest(client_secret, oauth_client.client_secret):
        raise OAuthError("invalid_client", "Invalid client credentials")

    # O token deve pertencer ao client informado (spec M5 regra 3)
    if rt.client_id != client_id:
        raise OAuthError("invalid_client", "Client mismatch")

    access_token = create_access_token({"sub": rt.user_id, "scope": rt.scope})
    at_jti = decode_token_claims(access_token).get("jti")
    new_rt = await rotate_refresh_token(db, rt, access_token_jti=at_jti)
    return access_token, new_rt


async def revoke_token(
    db: AsyncSession,
    token_str: str,
    hint: str | None,
    oauth_client: OAuthClient,
) -> None:
    """Revoga um access token ou refresh token (RFC 7009).

    Tenta ambos os tipos independente do hint (spec M7 regra 6).
    Nunca lança exceção — RFC 7009 §2.2 exige silêncio para tokens inexistentes.

    Ordem: hint='access_token' → tenta JWT primeiro; caso contrário, refresh primeiro.
    Se o primeiro tipo falhar, tenta o segundo (sistema sempre tenta ambos).
    """
    now = datetime.now(timezone.utc)

    async def _try_as_refresh() -> bool:
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token == token_str,
                RefreshToken.client_id == oauth_client.client_id,
                RefreshToken.revoked == False,  # noqa: E712
            )
        )
        rt = result.scalar_one_or_none()
        if rt is None:
            return False

        # Cascade: adiciona jti do access token derivado à blacklist
        if rt.access_token_jti:
            exp_at = now + timedelta(minutes=settings.access_token_expire_minutes)
            db.add(RevokedToken(jti=rt.access_token_jti, expires_at=exp_at))

        rt.revoked = True
        rt.revoked_at = now
        await db.commit()
        return True

    async def _try_as_access() -> bool:
        payload = decode_token_claims(token_str)
        jti = payload.get("jti")
        if not jti:
            return False
        exp_ts = payload.get("exp", 0)
        exp_at = (
            datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            if exp_ts > int(now.timestamp())
            else now + timedelta(minutes=settings.access_token_expire_minutes)
        )
        db.add(RevokedToken(jti=jti, expires_at=exp_at))
        await db.commit()
        return True

    if hint == "access_token":
        if not await _try_as_access():
            await _try_as_refresh()
    else:
        if not await _try_as_refresh():
            await _try_as_access()
