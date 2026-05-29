# Spec M2 — Login

**Status:** `[x] Spec` → `[x] Testes escritos` → `[x] Implementado` → `[ ] Revisado`

---

## Caso de uso

Um usuário registrado fornece e-mail e senha para obter um access token JWT. Este token será usado para autenticar requisições subsequentes e para iniciar fluxos OAuth2.

---

## Regras de negócio

1. O sistema deve verificar o hash da senha — nunca comparar texto plano.
2. A mensagem de erro para "e-mail não existe" e "senha errada" deve ser **idêntica** — não revelar qual campo está incorreto (proteção contra enumeração de usuários).
3. Usuários com `is_active = False` não podem fazer login (401).
4. O access token JWT deve conter os claims: `sub` (user id), `email`, `iat`, `exp`.
5. O token expira em 30 minutos por padrão (configurável via env var).
6. A verificação de senha deve ser protegida contra timing attacks (usar `secrets.compare_digest` ou equivalente).

---

## Contrato da API

### Request

```
POST /auth/login
Content-Type: application/json
```

```json
{
  "email": "joao@exemplo.com",
  "password": "Senha1234"
}
```

### Responses

**200 OK — Login bem-sucedido**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**401 Unauthorized — Credenciais inválidas**

```json
{
  "detail": "Invalid credentials"
}
```

> Mesma mensagem para e-mail inexistente E senha errada — nunca diferenciar.

---

## Schema Pydantic

```python
# schemas/token.py

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos
```

---

## Estrutura do JWT

```python
# Payload (claims)
{
    "sub": "550e8400-e29b-41d4-a716-446655440000",  # user id
    "email": "joao@exemplo.com",
    "iat": 1705312200,   # issued at (unix timestamp)
    "exp": 1705314000    # expires at (iat + 1800s)
}
```

O token é assinado com HS256 usando a `SECRET_KEY` do ambiente. A chave **nunca** deve estar hardcoded.

---

## Serviço — `services/token_service.py`

```python
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Gera um JWT assinado com os dados fornecidos."""
    ...

def decode_access_token(token: str) -> dict:
    """Decodifica e valida um JWT. Lança exceção se inválido ou expirado."""
    ...
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_token_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Token gerado é string JWT válida | dados de usuário | string com 3 segmentos separados por `.` |
| U2 | Claims corretos no payload | sub, email | decode retorna os mesmos valores |
| U3 | Token expira no tempo configurado | expires_delta=30min | claim `exp` = `iat` + 1800 |
| U4 | Token expirado lança exceção | token com exp no passado | `JWTError` ou `ExpiredSignatureError` |
| U5 | Token com assinatura adulterada lança exceção | alterar 1 char no token | `JWTError` |
| U6 | SECRET_KEY diferente invalida token | token gerado com chave A, verificado com chave B | `JWTError` |

### Testes unitários — `tests/unit/test_auth_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U7 | Autenticação com senha correta retorna usuário | usuário existente, senha correta | objeto User |
| U8 | Autenticação com senha errada retorna None | usuário existente, senha errada | None |
| U9 | Autenticação com e-mail inexistente retorna None | e-mail não cadastrado | None |

### Testes de integração — `tests/integration/test_login.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Login com credenciais válidas | e-mail e senha corretos | 200, access_token presente |
| I2 | Token retornado é JWT válido | resposta do login | decodificável com a SECRET_KEY |
| I3 | Claims do token estão corretos | login de usuário conhecido | sub == user.id, email == user.email |
| I4 | token_type é "bearer" | login válido | `token_type: "bearer"` |
| I5 | Senha errada | senha incorreta | 401, "Invalid credentials" |
| I6 | E-mail inexistente | e-mail não cadastrado | 401, "Invalid credentials" |
| I7 | Mensagem de erro idêntica | senha errada vs e-mail inexistente | mesmo `detail` nos dois casos |
| I8 | Usuário inativo não pode logar | is_active=False | 401 |
| I9 | Body vazio | `{}` | 422 |
| I10 | Campo password ausente | só e-mail | 422 |

---

## Variáveis de ambiente necessárias

```env
SECRET_KEY=sua-chave-secreta-muito-longa-e-aleatoria
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

---

## Dependências

- M1 (Registro) — precisa de usuários no banco

## Desbloqueado por este módulo

- M3 (OAuth Authorize) — o fluxo de autorização exige usuário autenticado
- M6 (Rotas protegidas) — o middleware de auth usa a lógica de decode_access_token deste módulo
