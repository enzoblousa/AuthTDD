# Spec M7 — Revogação de tokens

**Status:** `[ ] Spec` → `[ ] Testes escritos` → `[ ] Implementado` → `[ ] Revisado`

---

## Caso de uso

O usuário faz logout, ou um sistema de segurança detecta comprometimento. Os tokens ativos devem ser invalidados imediatamente, sem esperar a expiração natural.

Este endpoint implementa a **RFC 7009 — OAuth 2.0 Token Revocation**.

---

## Regras de negócio

1. O endpoint aceita tanto `access_token` quanto `refresh_token`.
2. **Sempre retorna 200** — a RFC 7009 especifica que não se deve revelar se um token existia ou era válido (proteção contra enumeração).
3. O `client_id` e `client_secret` são obrigatórios — apenas o dono do token pode revogá-lo.
4. Se um `refresh_token` for revogado, todos os `access_tokens` derivados dele também devem ser invalidados (revogação em cascata via blacklist de `jti`).
5. Se um `access_token` for revogado, apenas aquele token é adicionado à blacklist.
6. O `token_type_hint` é opcional e serve apenas como otimização de busca — o sistema deve tentar ambos se o hint não corresponder.

---

## Contrato da API

### Request

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
  ou via body:
```

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `token` | string | sim | O token a ser revogado |
| `token_type_hint` | string | não | `"access_token"` ou `"refresh_token"` |
| `client_id` | string | sim | ID do client |
| `client_secret` | string | sim | Secret do client |

### Response

**200 OK — Sempre** (token revogado, token inexistente, ou token de outro client)

```json
{}
```

> Corpo vazio. Nunca retornar erro por token inexistente ou inválido.

**401 Unauthorized — client_id/secret inválidos**

```json
{
  "error": "invalid_client"
}
```

> A única exceção — credenciais do client são verificadas antes de qualquer operação.

---

## Schema Pydantic

```python
# schemas/oauth.py

class RevokeRequest(BaseModel):
    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str
    client_secret: str
```

---

## Lógica de revogação

```python
async def revoke_token(token: str, hint: str | None, client: OAuthClient, db: AsyncSession):
    """
    Algoritmo:
    1. Se hint == "refresh_token" (ou sem hint): tentar como refresh token primeiro
       a. Buscar na tabela refresh_tokens
       b. Se encontrado e pertence ao client: marcar como revogado
       c. Buscar todos os access tokens derivados (pelo refresh_token_id) e adicionar jti à blacklist
    2. Se hint == "access_token" (ou refresh não encontrado): tentar como access token
       a. Decodificar o JWT (sem verificar expiração)
       b. Extrair o jti
       c. Adicionar à tabela revoked_tokens
    3. Se token não encontrado em nenhuma tabela: retornar sem erro (RFC 7009)
    """
    ...
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_token_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Revogar refresh token marca como revogado | refresh válido | `revoked == True` no banco |
| U2 | Revogar refresh token invalida access tokens derivados | refresh + access associado | jti do access na blacklist |
| U3 | Revogar access token adiciona jti à blacklist | access válido | jti presente em revoked_tokens |
| U4 | Token inexistente não lança exceção | token aleatório | sem erro |

### Testes de integração — `tests/integration/test_revocation.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Revogar access token → 200 | access token válido | 200 `{}` |
| I2 | Access token revogado não acessa rotas protegidas | usar token após revogar | 401 em /users/me |
| I3 | Revogar refresh token → 200 | refresh token válido | 200 `{}` |
| I4 | Refresh token revogado não pode ser usado para refresh | usar após revogar | 400 em /oauth/token |
| I5 | Revogar refresh token invalida access tokens derivados | revogar refresh, usar access | 401 em /users/me |
| I6 | Token inexistente retorna 200 | token aleatório | 200 `{}` |
| I7 | Token de outro client retorna 200 sem revogar | token de client B, credenciais de client A | 200 (sem revogar — RFC 7009) |
| I8 | client_secret errado → 401 | credenciais inválidas | 401 `invalid_client` |
| I9 | token_type_hint ausente → funciona normalmente | sem hint | 200, comportamento correto |
| I10 | token_type_hint errado → sistema tenta ambos | hint="access_token" mas enviou refresh | 200, revoga corretamente |

---

## Teste E2E — `tests/e2e/test_authorization_code_flow.py`

Este módulo completa o fluxo completo. O teste E2E deve cobrir:

```
1. Registrar usuário
2. Fazer login (obter access token interno)
3. Iniciar Authorization Code Flow (/oauth/authorize)
4. Trocar código por tokens (/oauth/token)
5. Acessar rota protegida com access token
6. Usar refresh token para obter novo access token
7. Revogar refresh token
8. Confirmar que access token derivado também foi invalidado
9. Confirmar que novo access token (pós-refresh) também foi invalidado
```

---

## Dependências

- M4 (Token Exchange) — access e refresh tokens emitidos
- M5 (Refresh Token) — família de tokens para revogação em cascata
- M6 (Rotas protegidas) — blacklist de jti usada para validar access tokens

## Este módulo completa o sistema

Com M7 implementado e todos os testes passando, o sistema está completo. Executar:

```bash
pytest --cov=app --cov-report=term-missing
```

Meta: 85%+ de cobertura total, 100% em `core/security.py`.
