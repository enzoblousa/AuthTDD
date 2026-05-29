# Spec M3 — OAuth2 Authorization Endpoint

**Status:** `[ ] Spec` → `[ ] Testes escritos` → `[ ] Implementado` → `[ ] Revisado`

---

## Caso de uso

Uma aplicação cliente (client_id registrado no sistema) redireciona o usuário para o endpoint de autorização. O sistema autentica o usuário (via session ou token), exibe (ou simula) a tela de consentimento, e redireciona de volta com um `authorization_code` de uso único.

Este é o primeiro passo do **Authorization Code Flow com PKCE**.

---

## Regras de negócio

1. O `client_id` deve estar cadastrado no sistema.
2. O `redirect_uri` deve ser exatamente igual a uma URI registrada para aquele client (sem trailing slash, sem variações).
3. O `response_type` deve ser `"code"` — outros valores retornam erro.
4. O `state` deve ser preservado intacto no redirect de volta — o client usa para proteção contra CSRF.
5. **PKCE é obrigatório**: `code_challenge` e `code_challenge_method=S256` são requeridos.
6. O `code_challenge_method` deve ser `S256` — `plain` não é aceito (inseguro).
7. O authorization code gerado deve:
   - Ser criptograficamente aleatório (mínimo 32 bytes de entropia)
   - Expirar em 10 minutos
   - Ser de uso único (invalidado após a primeira troca)
8. O code e o code_challenge devem ser armazenados juntos para verificação PKCE na etapa de token exchange (M4).

---

## Contrato da API

### Request

```
GET /oauth/authorize
```

Query parameters:

| Parâmetro | Tipo | Obrigatório | Descrição |
|-----------|------|-------------|-----------|
| `response_type` | string | sim | Deve ser `"code"` |
| `client_id` | string | sim | ID do client registrado |
| `redirect_uri` | string | sim | Deve corresponder ao cadastro |
| `scope` | string | não | Escopos separados por espaço. Default: `"openid"` |
| `state` | string | recomendado | String opaca para proteção CSRF |
| `code_challenge` | string | sim | base64url(sha256(code_verifier)) |
| `code_challenge_method` | string | sim | Deve ser `"S256"` |

### Responses

**302 Found — Autorização bem-sucedida**

```
Location: https://app.exemplo.com/callback?code=abc123xyz&state=random_state_value
```

**302 Found — Erro (redirect com erro)**

Erros que não comprometem o client fazem redirect com parâmetros de erro:

```
Location: https://app.exemplo.com/callback?error=access_denied&state=...
```

**400 Bad Request — Erros que impedem o redirect**

Quando `client_id` ou `redirect_uri` são inválidos, **não** se deve redirecionar — retornar 400 diretamente:

```json
{
  "detail": "Invalid client_id or redirect_uri"
}
```

> Nunca redirecionar para URIs não confiáveis — isso poderia vazar o authorization code.

---

## Schema Pydantic

```python
# schemas/oauth.py

class AuthorizeRequest(BaseModel):
    response_type: Literal["code"]
    client_id: str
    redirect_uri: HttpUrl
    scope: str = "openid"
    state: str | None = None
    code_challenge: str
    code_challenge_method: Literal["S256"]
```

---

## Modelo de dados — Authorization Code

```python
# models/token.py

class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    id: UUID (primary key)
    code: str (unique, indexed)           # o código enviado ao client
    client_id: str (FK → oauth_clients)
    user_id: UUID (FK → users)
    redirect_uri: str
    scope: str
    state: str | None
    code_challenge: str                   # armazenado para verificação PKCE
    code_challenge_method: str            # "S256"
    expires_at: datetime                  # created_at + 10 minutos
    used: bool (default False)            # invalidado após o primeiro uso
    created_at: datetime
```

---

## Serviço — `services/oauth_service.py`

```python
def generate_authorization_code(
    client_id: str,
    user_id: UUID,
    redirect_uri: str,
    scope: str,
    state: str | None,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    """Gera, persiste e retorna um authorization code."""
    ...

def validate_authorize_request(
    client_id: str,
    redirect_uri: str,
) -> OAuthClient:
    """Valida client_id e redirect_uri. Lança HTTPException se inválido."""
    ...
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_oauth_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Código gerado tem entropia suficiente | — | len >= 43 chars (256 bits em base64url) |
| U2 | Dois códigos gerados são diferentes | gerar duas vezes | códigos distintos |
| U3 | Code expira em 10 minutos | código criado agora | `expires_at` == `now + 10min` |
| U4 | Código marcado como não-usado ao criar | novo código | `used == False` |

### Testes de integração — `tests/integration/test_oauth_authorize.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Request válido retorna redirect 302 | todos os params corretos | 302, Location com `?code=` |
| I2 | State preservado no redirect | state="meu_state" | Location contém `&state=meu_state` |
| I3 | Code presente no Location header | request válido | Location contém `code=` não vazio |
| I4 | client_id inexistente → 400 | client_id="nao_existe" | 400, sem redirect |
| I5 | redirect_uri não cadastrada → 400 | uri não registrada no client | 400, sem redirect |
| I6 | response_type inválido → redirect com erro | response_type="token" | redirect com `error=unsupported_response_type` |
| I7 | code_challenge ausente → erro | sem code_challenge | 422 ou redirect com erro |
| I8 | code_challenge_method=plain → erro | method="plain" | 422 ou redirect com erro |
| I9 | scope inválido → redirect com erro | scope="admin" (não registrado) | redirect com `error=invalid_scope` |
| I10 | State ausente → redirect sem state | sem state param | Location sem `state=` (não quebra) |
| I11 | Código gerado tem expiração futura | request válido | código no banco com expires_at > now |
| I12 | Código gerado está como não-usado | request válido | `used == False` no banco |

---

## Geração do PKCE pelo client (referência)

```python
import hashlib, base64, secrets

# Client gera antes do redirect:
code_verifier = secrets.token_urlsafe(32)  # 43+ chars

# Client calcula o challenge:
digest = hashlib.sha256(code_verifier.encode()).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

# Client envia code_challenge na URL, guarda code_verifier para a etapa de token
```

---

## Dependências

- M1 (Registro) — usuário precisa existir
- M2 (Login) — usuário precisa estar autenticado para autorizar
- Client OAuth2 precisa estar cadastrado no banco (`oauth_clients`)

## Desbloqueado por este módulo

- M4 (Token Exchange) — precisa do authorization code gerado aqui
