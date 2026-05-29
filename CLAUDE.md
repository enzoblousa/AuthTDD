# auth-tdd — Sistema de Autenticação OAuth2

> Projeto desenvolvido com **Spec Driven Development + Test Driven Development**  
> Stack: Python 3.12 · FastAPI · pytest · SQLite/PostgreSQL · JWT

---

## Visão geral

Este projeto é um sistema de autenticação OAuth2 construído do zero usando as metodologias SDD e TDD. O objetivo é duplo: produzir um sistema funcional e seguro, e documentar o processo de desenvolvimento orientado por testes para fins didáticos (seminário).

A regra central do projeto:

> **Nenhuma linha de código de produção é escrita sem um teste falhando antes.**

---

## Metodologias

### Spec Driven Development (SDD)

Antes de qualquer teste ou código, a feature é especificada:

1. Descrição do caso de uso em linguagem natural
2. Contrato da API (endpoint, request, response, erros)
3. Modelos de dados (Pydantic schemas)
4. Só então: escrever o teste

### Test Driven Development (TDD)

O ciclo obrigatório para cada feature:

```
🔴 RED    → Escrever o teste que descreve o comportamento esperado
🟢 GREEN  → Escrever o código mínimo para o teste passar
♻️ REFACTOR → Melhorar o código sem quebrar os testes
```

---

## Stack técnica

| Camada         | Tecnologia               | Motivo                                      |
|----------------|--------------------------|---------------------------------------------|
| Runtime        | Python 3.12              | Clareza e expressividade                    |
| Framework      | FastAPI                  | Schema-first nativo, OpenAPI automático     |
| Validação      | Pydantic v2              | Schemas são a spec em código                |
| Testes         | pytest + pytest-asyncio  | Sintaxe expressiva, fixtures poderosas      |
| HTTP test      | httpx (AsyncClient)      | Testes de integração assíncronos            |
| Banco de dados | SQLite (dev) / PostgreSQL (prod) | Simplicidade no dev, robustez na prod |
| ORM            | SQLAlchemy 2.0           | Async support, type-safe                    |
| Tokens         | python-jose + passlib    | JWT + bcrypt para senhas                    |
| Spec           | OpenAPI 3.1 (gerado pelo FastAPI) | Documentação sempre atualizada      |
| Coverage       | pytest-cov               | Relatório de cobertura de testes            |

---

## Estrutura do projeto

```
auth-tdd/
├── app/
│   ├── __init__.py
│   ├── main.py                  # Entry point FastAPI
│   ├── config.py                # Configurações (pydantic-settings)
│   ├── database.py              # Engine, session, base
│   │
│   ├── models/                  # SQLAlchemy models (tabelas)
│   │   ├── user.py
│   │   ├── oauth_client.py
│   │   └── token.py
│   │
│   ├── schemas/                 # Pydantic schemas (contratos da API)
│   │   ├── user.py
│   │   ├── oauth.py
│   │   └── token.py
│   │
│   ├── routers/                 # Endpoints organizados por domínio
│   │   ├── auth.py              # /auth/register, /auth/login
│   │   ├── oauth.py             # /oauth/authorize, /oauth/token, /oauth/revoke
│   │   └── users.py             # /users/me (rota protegida)
│   │
│   ├── services/                # Lógica de negócio (testável isoladamente)
│   │   ├── auth_service.py
│   │   ├── token_service.py
│   │   └── oauth_service.py
│   │
│   └── core/                    # Utilitários centrais
│       ├── security.py          # Hash de senha, JWT
│       ├── dependencies.py      # FastAPI Depends (get_current_user etc.)
│       └── exceptions.py        # HTTP exceptions customizadas
│
├── tests/
│   ├── conftest.py              # Fixtures globais (client, db, usuários)
│   ├── unit/                    # Testes unitários (sem I/O)
│   │   ├── test_security.py
│   │   ├── test_token_service.py
│   │   └── test_auth_service.py
│   ├── integration/             # Testes de endpoints (com banco em memória)
│   │   ├── test_register.py
│   │   ├── test_login.py
│   │   ├── test_oauth_flow.py
│   │   └── test_protected_routes.py
│   └── e2e/                     # Fluxo completo OAuth2
│       └── test_authorization_code_flow.py
│
├── specs/                       # Especificações antes do código
│   ├── 01_user_registration.md
│   ├── 02_login.md
│   ├── 03_oauth_authorize.md
│   ├── 04_oauth_token.md
│   ├── 05_token_refresh.md
│   └── 06_revocation.md
│
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── README.md
└── claude.md                    # Este arquivo
```

---

## Módulos e ordem de desenvolvimento

Os módulos devem ser implementados nesta ordem, sempre seguindo o ciclo SDD → TDD.

### M1 · Registro de usuário

**Spec:** `specs/01_user_registration.md`

```
POST /auth/register
Body: { email, password, name }
201: { id, email, name, created_at }
400: email já cadastrado
422: validação de campos (email inválido, senha fraca)
```

Casos de teste obrigatórios:
- Registro com dados válidos → 201
- Email duplicado → 400
- Email com formato inválido → 422
- Senha com menos de 8 caracteres → 422
- Senha armazenada como hash (nunca em plain text)

---

### M2 · Login (Resource Owner Password — interno)

**Spec:** `specs/02_login.md`

```
POST /auth/login
Body: { email, password }
200: { access_token, token_type, expires_in }
401: credenciais inválidas
```

Casos de teste obrigatórios:
- Login com credenciais válidas → 200 com JWT
- Senha errada → 401
- Email inexistente → 401
- JWT contém claims corretos (sub, exp, iat)

---

### M3 · OAuth2 — Authorization Code Flow

**Spec:** `specs/03_oauth_authorize.md`

```
GET /oauth/authorize
Query: response_type=code, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method
302: redirect para redirect_uri com ?code=...&state=...
400: client_id inválido
400: redirect_uri não autorizada
```

Casos de teste obrigatórios:
- Parâmetros válidos → redirect com código
- state é preservado no redirect
- client_id inexistente → 400
- redirect_uri não cadastrada no client → 400
- code_challenge ausente (PKCE obrigatório) → 400

---

### M4 · OAuth2 — Token Exchange

**Spec:** `specs/04_oauth_token.md`

```
POST /oauth/token
Body: grant_type=authorization_code, code, redirect_uri, client_id, client_secret, code_verifier
200: { access_token, refresh_token, token_type, expires_in, scope }
400: código expirado ou inválido
400: code_verifier falha na verificação PKCE
```

Casos de teste obrigatórios:
- Troca válida → 200 com access + refresh token
- Código já usado → 400 (código de autorização é one-time)
- code_verifier inválido → 400
- client_secret errado → 401
- Código expirado (> 10 min) → 400

---

### M5 · Refresh Token

**Spec:** `specs/05_token_refresh.md`

```
POST /oauth/token
Body: grant_type=refresh_token, refresh_token, client_id, client_secret
200: { access_token, refresh_token (rotacionado), expires_in }
400: refresh_token inválido ou revogado
```

Casos de teste obrigatórios:
- Refresh válido → novo access token + novo refresh token
- Refresh token rotacionado (token antigo inválido após uso)
- Refresh token revogado → 400

---

### M6 · Rotas protegidas e scopes

**Spec:** `specs/06_protected_routes.md`

```
GET /users/me
Header: Authorization: Bearer <access_token>
200: { id, email, name, scopes }
401: token ausente ou inválido
403: token sem o scope necessário
```

Casos de teste obrigatórios:
- Token válido → 200 com dados do usuário
- Token expirado → 401
- Token sem scope `profile` → 403
- Token revogado → 401

---

### M7 · Revogação de tokens

**Spec:** `specs/07_revocation.md`

```
POST /oauth/revoke
Body: token, token_type_hint, client_id, client_secret
200: sempre (RFC 7009 — não revela se token existe)
```

Casos de teste obrigatórios:
- Revogar access token → token inválido em seguida
- Revogar refresh token → refresh e todos os access tokens derivados inválidos
- Revogar token inexistente → 200 (sem revelar informação)

---

## Setup do ambiente

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/auth-tdd
cd auth-tdd

# Criar ambiente virtual
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Instalar dependências
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Configurar variáveis de ambiente
cp .env.example .env
# Editar .env com SECRET_KEY, DATABASE_URL etc.

# Rodar os testes
pytest

# Rodar com coverage
pytest --cov=app --cov-report=html

# Iniciar o servidor
uvicorn app.main:app --reload
```

---

## Comandos de teste

```bash
# Todos os testes
pytest

# Apenas unitários
pytest tests/unit/

# Apenas integração
pytest tests/integration/

# Apenas e2e
pytest tests/e2e/

# Com output verboso
pytest -v

# Parar no primeiro erro
pytest -x

# Coverage completo
pytest --cov=app --cov-report=term-missing --cov-report=html

# Rodar um teste específico
pytest tests/integration/test_oauth_flow.py::test_authorization_code_success -v
```

---

## Convenções do projeto

### Nomenclatura de testes

```python
# Padrão: test_<ação>_<condição>_<resultado_esperado>
def test_register_with_valid_data_returns_201(): ...
def test_register_with_duplicate_email_returns_400(): ...
def test_login_with_wrong_password_returns_401(): ...
def test_token_exchange_with_used_code_returns_400(): ...
```

### Estrutura de um teste

```python
async def test_register_with_valid_data_returns_201(client: AsyncClient):
    # Arrange — preparar os dados
    payload = {"email": "user@example.com", "password": "Str0ng!Pass", "name": "Test User"}

    # Act — executar a ação
    response = await client.post("/auth/register", json=payload)

    # Assert — verificar o resultado
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]
    assert "password" not in data  # nunca expor senha
```

### Fixtures globais (conftest.py)

```python
@pytest.fixture
async def client(db_session):
    """Cliente HTTP para testes de integração."""
    ...

@pytest.fixture
async def authenticated_user(client):
    """Usuário já registrado e com token válido."""
    ...

@pytest.fixture
async def oauth_client(db_session):
    """Client OAuth2 cadastrado para testes."""
    ...
```

---

## Fluxo OAuth2 (Authorization Code + PKCE)

```
1. App gera code_verifier (random string)
2. App gera code_challenge = base64url(sha256(code_verifier))
3. Redirect → GET /oauth/authorize?...&code_challenge=...&code_challenge_method=S256
4. Servidor autentica usuário, gera authorization_code
5. Redirect de volta → GET redirect_uri?code=...&state=...
6. App troca o código → POST /oauth/token (com code_verifier)
7. Servidor verifica PKCE: sha256(code_verifier) == code_challenge
8. Servidor retorna access_token + refresh_token
9. App usa access_token no header: Authorization: Bearer <token>
```

---

## Segurança implementada

- Senhas armazenadas com bcrypt (fator de custo 12)
- JWT assinado com HS256 (segredo via env var, nunca hardcoded)
- PKCE obrigatório em todos os fluxos Authorization Code
- Authorization codes são one-time use e expiram em 10 minutos
- Refresh tokens são rotacionados a cada uso
- Revogação em cascata (revogar refresh invalida todos os access tokens derivados)
- Rate limiting nos endpoints de autenticação (via slowapi)
- Proteção contra timing attacks nas comparações de credenciais

---

## Cronograma de desenvolvimento

| Dia | Módulo | Foco |
|-----|--------|------|
| 1 | Setup + M1 (Registro) | Ambiente, estrutura, primeiro ciclo TDD |
| 2 | M2 (Login) + M3 (Authorize) | JWT, início do fluxo OAuth2 |
| 3 | M4 (Token Exchange) + PKCE | Coração do OAuth2 |
| 4 | M5 (Refresh) + M6 (Proteção) | Scopes, middleware |
| 5 | M7 (Revogação) + Coverage | Finalização, 90%+ cobertura |

---

## Objetivos de cobertura

| Camada | Meta |
|--------|------|
| `app/core/security.py` | 100% |
| `app/services/` | 95%+ |
| `app/routers/` | 90%+ |
| Total do projeto | 85%+ |

---

## Referências

- [RFC 6749 — OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 7009 — Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [FastAPI — Security](https://fastapi.tiangolo.com/tutorial/security/)
- [pytest — Getting Started](https://docs.pytest.org/en/stable/)
- [Test-Driven Development by Example — Kent Beck](https://www.oreilly.com/library/view/test-driven-development/0321146530/)