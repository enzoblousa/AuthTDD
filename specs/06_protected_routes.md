# Spec M6 — Rotas protegidas e scopes

**Status:** `[ ] Spec` → `[ ] Testes escritos` → `[ ] Implementado` → `[ ] Revisado`

---

## Caso de uso

Rotas da API que exigem autenticação devem verificar o `Authorization: Bearer <token>` em cada request. Além de validar a autenticidade do JWT, o sistema verifica se o token possui os scopes necessários para acessar aquele recurso.

---

## Regras de negócio

1. Todo endpoint protegido exige o header `Authorization: Bearer <token>`.
2. O token deve ser um JWT válido, assinado com a `SECRET_KEY` correta.
3. O token não pode estar expirado.
4. O token não pode estar na blacklist (revogado via `/oauth/revoke`).
5. Cada endpoint pode exigir um ou mais scopes específicos — se o token não tiver o scope necessário, retornar `403`.
6. O `current_user` extraído do token deve ser um usuário ativo (`is_active = True`).

---

## Scopes disponíveis

| Scope | Acesso liberado |
|-------|-----------------|
| `openid` | Identidade básica (sub/id) |
| `profile` | Nome, e-mail, created_at |
| `email` | Apenas o e-mail |
| `offline_access` | Permite emissão de refresh token |

---

## Contrato da API

### Endpoint protegido de exemplo: perfil do usuário

```
GET /users/me
Authorization: Bearer <access_token>
Required scope: profile
```

**200 OK**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "João Silva",
  "email": "joao@exemplo.com",
  "is_active": true,
  "scopes": ["openid", "profile"],
  "created_at": "2024-01-15T10:30:00Z"
}
```

**401 Unauthorized — Token ausente**

```json
{
  "detail": "Not authenticated"
}
```

**401 Unauthorized — Token inválido ou expirado**

```json
{
  "detail": "Could not validate credentials"
}
```

**403 Forbidden — Scope insuficiente**

```json
{
  "detail": "Insufficient scope. Required: profile"
}
```

---

## Implementação do middleware

```python
# core/dependencies.py

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Dependency injetada em qualquer rota que exija autenticação.
    1. Extrai o token do header Authorization
    2. Decodifica e valida o JWT
    3. Verifica se o jti (JWT ID) não está na blacklist
    4. Busca o usuário no banco pelo sub (user_id)
    5. Verifica is_active
    6. Retorna o User
    """
    ...

def require_scope(*scopes: str):
    """
    Dependency factory para verificar scopes.
    Uso: Depends(require_scope("profile"))
    """
    async def check_scope(token_data: TokenData = Depends(get_token_data)):
        for scope in scopes:
            if scope not in token_data.scopes:
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient scope. Required: {scope}"
                )
    return check_scope
```

### Uso em um router

```python
# routers/users.py

@router.get("/users/me")
async def get_my_profile(
    current_user: User = Depends(get_current_user),
    _: None = Depends(require_scope("profile")),
):
    return current_user
```

---

## Blacklist de tokens

Tokens revogados são armazenados pelo seu `jti` (JWT ID — claim único por token):

```python
# models/token.py

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: str (primary key)       # claim "jti" do JWT
    revoked_at: datetime
    expires_at: datetime         # para limpeza periódica — não precisamos guardar para sempre
```

> O `jti` deve ser incluído como claim em todos os JWTs gerados (ver M2).

---

## Casos de teste

### Testes unitários — `tests/unit/test_auth_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Token válido retorna user correto | JWT com sub válido | objeto User |
| U2 | Token expirado lança 401 | JWT com exp no passado | HTTPException 401 |
| U3 | Token com assinatura inválida lança 401 | JWT adulterado | HTTPException 401 |
| U4 | Usuário inativo lança 401 | is_active=False | HTTPException 401 |
| U5 | require_scope com scope presente não lança | scopes=["profile"] | sem exceção |
| U6 | require_scope com scope ausente lança 403 | scopes=["openid"], required="profile" | HTTPException 403 |

### Testes de integração — `tests/integration/test_protected_routes.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | GET /users/me com token válido → 200 | token com scope "profile" | 200, dados do usuário |
| I2 | GET /users/me sem header Authorization → 401 | sem token | 401 |
| I3 | GET /users/me com token malformado → 401 | "Bearer not_a_jwt" | 401 |
| I4 | GET /users/me com token expirado → 401 | token com exp no passado | 401 |
| I5 | GET /users/me com token sem scope "profile" → 403 | token com scope="openid" | 403 |
| I6 | GET /users/me com token revogado → 401 | jti na blacklist | 401 |
| I7 | Resposta contém os scopes do token | token com scope="openid profile" | scopes presente na resposta |
| I8 | Usuário inativo não acessa rota protegida | is_active=False | 401 |

---

## Dependências

- M2 (Login) — lógica de decode_access_token
- M4 (Token Exchange) — JWTs emitidos com `jti` e `scope`

## Desbloqueado por este módulo

- M7 (Revogação) — usa a blacklist de `jti` implementada aqui
