# Spec M4 — OAuth2 Token Exchange

**Status:** `[ ] Spec` → `[ ] Testes escritos` → `[ ] Implementado` → `[ ] Revisado`

---

## Caso de uso

O client trocou o `authorization_code` recebido no redirect por um `access_token` e um `refresh_token`. Esta é a etapa mais crítica do fluxo — aqui o PKCE é verificado e os tokens reais são emitidos.

---

## Regras de negócio

1. O `grant_type` deve ser `"authorization_code"`.
2. O `code` deve existir no banco, não estar expirado e não ter sido usado antes.
3. O `redirect_uri` deve ser **idêntico** ao usado no request de autorização (M3).
4. O `client_id` deve corresponder ao client que gerou o código.
5. **Verificação PKCE obrigatória**: `sha256(code_verifier)` deve ser igual ao `code_challenge` armazenado.
6. O authorization code deve ser marcado como `used = True` imediatamente após a troca — qualquer tentativa de reuso retorna erro.
7. O access token JWT expira em 30 minutos.
8. O refresh token é uma string opaca (não JWT), armazenada no banco, expira em 30 dias.
9. Em caso de qualquer erro de validação, retornar `400` com `error` no formato OAuth2 (RFC 6749 §5.2).

---

## Contrato da API

### Request

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `grant_type` | string | sim | `"authorization_code"` |
| `code` | string | sim | O código recebido no redirect |
| `redirect_uri` | string | sim | Idêntico ao usado em /authorize |
| `client_id` | string | sim | ID do client |
| `client_secret` | string | sim | Secret do client |
| `code_verifier` | string | sim | O verifier original (PKCE) |

### Responses

**200 OK — Troca bem-sucedida**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
  "token_type": "bearer",
  "expires_in": 1800,
  "scope": "openid profile"
}
```

**400 Bad Request — Erros de validação**

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has already been used"
}
```

Possíveis valores de `error` (RFC 6749):

| error | Situação |
|-------|----------|
| `invalid_grant` | código inválido, expirado, já usado, redirect_uri diverge |
| `invalid_client` | client_id/secret inválidos |
| `invalid_request` | parâmetros ausentes ou malformados |
| `unsupported_grant_type` | grant_type diferente de "authorization_code" |

---

## Schema Pydantic

```python
# schemas/oauth.py

class TokenRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: HttpUrl
    client_id: str
    client_secret: str
    code_verifier: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str
```

---

## Modelo de dados — Refresh Token

```python
# models/token.py

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: UUID (primary key)
    token: str (unique, indexed)        # string opaca, não JWT
    user_id: UUID (FK → users)
    client_id: str (FK → oauth_clients)
    scope: str
    expires_at: datetime                # now + 30 dias
    revoked: bool (default False)
    revoked_at: datetime | None
    replaced_by: UUID | None            # para rotação — aponta para o novo refresh token
    created_at: datetime
```

---

## Verificação PKCE (detalhe de implementação)

```python
import hashlib, base64

def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """
    Recalcula o challenge a partir do verifier e compara.
    Usa compare_digest para proteção contra timing attacks.
    """
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, code_challenge)
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_token_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | verify_pkce com verifier correto | verifier que gerou o challenge | True |
| U2 | verify_pkce com verifier errado | verifier diferente | False |
| U3 | verify_pkce com verifier vazio | "" | False |
| U4 | Refresh token gerado é string opaca | — | não decodificável como JWT |
| U5 | Dois refresh tokens são diferentes | gerar duas vezes | strings distintas |

### Testes de integração — `tests/integration/test_oauth_token.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Troca válida retorna 200 com tokens | tudo correto | 200, access_token + refresh_token |
| I2 | access_token é JWT válido | troca bem-sucedida | decodificável, claims corretos |
| I3 | scope na resposta é o solicitado em /authorize | scope="openid profile" | resposta contém scope correto |
| I4 | Código usado uma segunda vez → 400 | mesmo code duas vezes | segundo request → `invalid_grant` |
| I5 | code_verifier errado → 400 | verifier diferente do que gerou o challenge | `invalid_grant` |
| I6 | code_verifier ausente → 400 | sem code_verifier | `invalid_request` |
| I7 | Código expirado → 400 | code com expires_at no passado | `invalid_grant` |
| I8 | redirect_uri diferente → 400 | uri diferente da usada em /authorize | `invalid_grant` |
| I9 | client_secret errado → 400 | secret incorreto | `invalid_client` |
| I10 | client_id não confere com o código → 400 | code gerado por outro client | `invalid_grant` |
| I11 | grant_type errado → 400 | grant_type="password" | `unsupported_grant_type` |
| I12 | Após troca, código marcado como usado | troca válida | `used == True` no banco |
| I13 | Refresh token salvo no banco | troca válida | token presente em refresh_tokens |
| I14 | Refresh token tem expiração em ~30 dias | troca válida | `expires_at` ~= now + 30d |

---

## Dependências

- M3 (Authorize) — precisa de um authorization code válido com code_challenge
- Client OAuth2 cadastrado com client_secret

## Desbloqueado por este módulo

- M5 (Refresh Token) — precisa de refresh tokens emitidos aqui
- M6 (Rotas protegidas) — usa os access tokens gerados aqui
