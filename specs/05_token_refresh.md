# Spec M5 — Refresh Token

**Status:** `[ ] Spec` → `[ ] Testes escritos` → `[ ] Implementado` → `[ ] Revisado`

---

## Caso de uso

O access token do usuário expirou (30 minutos). Em vez de iniciar um novo fluxo de autorização completo, o client usa o `refresh_token` para obter um novo par de tokens silenciosamente, sem interação do usuário.

---

## Regras de negócio

1. O `grant_type` deve ser `"refresh_token"`.
2. O refresh token deve existir no banco, não estar revogado e não ter expirado.
3. O `client_id` e `client_secret` devem corresponder ao client que emitiu o refresh token.
4. **Rotação obrigatória**: a cada uso, o refresh token antigo é revogado e um novo é emitido. O campo `replaced_by` aponta para o novo token (auditoria).
5. **Detecção de reuso**: se um refresh token já revogado for apresentado novamente, revogar **toda a família de tokens** daquele usuário/client (possível roubo de token). Retornar `400`.
6. O novo access token herda o mesmo `scope` do refresh token original.
7. O novo refresh token herda a mesma `expires_at` do token original — não é renovado a cada uso.

---

## Contrato da API

### Request

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `grant_type` | string | sim | `"refresh_token"` |
| `refresh_token` | string | sim | O refresh token emitido em M4 |
| `client_id` | string | sim | ID do client |
| `client_secret` | string | sim | Secret do client |

### Responses

**200 OK — Refresh bem-sucedido**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "novo_refresh_token_rotacionado...",
  "token_type": "bearer",
  "expires_in": 1800,
  "scope": "openid profile"
}
```

**400 Bad Request — Token inválido**

```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token is expired or revoked"
}
```

---

## Schema Pydantic

```python
# schemas/oauth.py (adicionar ao existente)

class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    client_id: str
    client_secret: str
```

> O endpoint `POST /oauth/token` já existe (M4). Aqui usamos um `grant_type` diferente — o router despacha para o handler correto com base no `grant_type`.

---

## Lógica de rotação

```python
async def rotate_refresh_token(old_token: RefreshToken, db: AsyncSession) -> RefreshToken:
    """
    1. Cria novo refresh token com mesmo user_id, client_id, scope
    2. Seta old_token.revoked = True
    3. Seta old_token.replaced_by = new_token.id
    4. Persiste ambos atomicamente (transação)
    5. Retorna o novo token
    """
    ...
```

---

## Lógica de detecção de reuso (token theft detection)

```python
async def handle_refresh_token_reuse(token_str: str, db: AsyncSession):
    """
    Se o token existe mas já está revogado:
    - Revogar todos os refresh tokens ativos do mesmo user+client
    - Logar o evento como possível comprometimento
    - Retornar 400 invalid_grant
    """
    ...
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_token_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Novo refresh token é diferente do antigo | rotação | tokens distintos |
| U2 | Token antigo marcado como revogado após rotação | rotação | `old.revoked == True` |
| U3 | replaced_by aponta para o novo token | rotação | `old.replaced_by == new.id` |
| U4 | Novo token herda scope do antigo | rotação | `new.scope == old.scope` |
| U5 | Novo token herda expires_at do antigo | rotação | `new.expires_at == old.expires_at` |

### Testes de integração — `tests/integration/test_token_refresh.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Refresh válido retorna 200 com novos tokens | refresh válido | 200, novo access + refresh token |
| I2 | Novo access token é JWT válido | refresh bem-sucedido | decodificável |
| I3 | Novo refresh token é diferente do original | comparar antes/depois | strings diferentes |
| I4 | Refresh token antigo inválido após rotação | usar token antigo novamente | 400, `invalid_grant` |
| I5 | Novo access token tem os scopes corretos | scope original="openid profile" | novo token com mesmo scope |
| I6 | Refresh token expirado → 400 | token com expires_at no passado | `invalid_grant` |
| I7 | Refresh token revogado → 400 + revoga família | token já revogado | 400 + todos os tokens do user/client revogados |
| I8 | client_secret errado → 400 | secret incorreto | `invalid_client` |
| I9 | client_id não confere → 400 | token de outro client | `invalid_client` |
| I10 | grant_type="refresh_token" com token ausente | sem refresh_token | 422 |

---

## Dependências

- M4 (Token Exchange) — precisa de refresh tokens emitidos

## Desbloqueado por este módulo

- M7 (Revogação) — a lógica de revogação de família usa a estrutura de replaced_by
