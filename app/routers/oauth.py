"""Endpoints OAuth2 (M3+)."""

import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query
from sqlalchemy import select
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.exceptions import OAuthError
from app.database import get_db
from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.services.oauth_service import (
    exchange_code_for_tokens,
    generate_authorization_code,
    refresh_token_grant,
    revoke_token,
    validate_authorize_request,
)
from app.services.token_service import access_token_expires_in

router = APIRouter(prefix="/oauth", tags=["oauth"])


def _error_redirect(redirect_uri: str, error: str, state: str | None) -> RedirectResponse:
    params: dict = {"error": error}
    if state is not None:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: str | None = Query(None),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Authorization Code endpoint (RFC 6749 §4.1.1) com PKCE obrigatório."""
    oauth_client = await validate_authorize_request(db, client_id, redirect_uri)

    if response_type != "code":
        return _error_redirect(redirect_uri, "unsupported_response_type", state)

    if code_challenge_method != "S256":
        return _error_redirect(redirect_uri, "invalid_request", state)

    requested_scopes = set(scope.split())
    allowed_scopes = set(oauth_client.get_scopes())
    if not requested_scopes.issubset(allowed_scopes):
        return _error_redirect(redirect_uri, "invalid_scope", state)

    auth_code = await generate_authorization_code(
        db=db,
        client_id=client_id,
        user_id=str(current_user.id),
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    params: dict = {"code": auth_code.code}
    if state is not None:
        params["state"] = state

    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.post("/token")
async def token(
    grant_type: str = Form(...),
    # authorization_code fields (M4)
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    # common fields
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    # refresh_token fields (M5)
    refresh_token: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Token endpoint — despacha por grant_type (RFC 6749)."""
    if grant_type == "authorization_code":
        if code_verifier is None:
            return _oauth_error("invalid_request", "code_verifier is required")
        if not all([code, redirect_uri, client_id, client_secret]):
            return _oauth_error("invalid_request", "Missing required parameters")
        try:
            access_token, rt = await exchange_code_for_tokens(
                db=db,
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
                code_verifier=code_verifier,
            )
        except OAuthError as exc:
            return _oauth_error(exc.error, exc.description, exc.status_code)
        return {
            "access_token": access_token,
            "refresh_token": rt.token,
            "token_type": "bearer",
            "expires_in": access_token_expires_in(),
            "scope": rt.scope,
        }

    if grant_type == "refresh_token":
        if refresh_token is None:
            return JSONResponse(status_code=422, content={"detail": "refresh_token is required"})
        if not all([client_id, client_secret]):
            return _oauth_error("invalid_request", "Missing required parameters")
        try:
            access_token, new_rt = await refresh_token_grant(
                db=db,
                refresh_token_str=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
            )
        except OAuthError as exc:
            return _oauth_error(exc.error, exc.description, exc.status_code)
        return {
            "access_token": access_token,
            "refresh_token": new_rt.token,
            "token_type": "bearer",
            "expires_in": access_token_expires_in(),
            "scope": new_rt.scope,
        }

    return _oauth_error("unsupported_grant_type", f"Unsupported grant type: {grant_type}")


@router.post("/revoke")
async def revoke(
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Token Revocation endpoint (RFC 7009 §2).

    Sempre retorna 200 — exceto credenciais de client inválidas (401).
    """
    if not client_id or not client_secret:
        return JSONResponse(
            status_code=401, content={"error": "invalid_client"}
        )

    result = await db.execute(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.is_active == True,  # noqa: E712
        )
    )
    oauth_client = result.scalar_one_or_none()
    if oauth_client is None or not secrets.compare_digest(
        client_secret, oauth_client.client_secret
    ):
        return JSONResponse(
            status_code=401, content={"error": "invalid_client"}
        )

    await revoke_token(db, token, token_type_hint, oauth_client)
    return JSONResponse(status_code=200, content={})
