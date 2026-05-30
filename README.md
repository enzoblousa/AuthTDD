# auth-tdd

Sistema de autenticação **OAuth2 com PKCE** construído do zero seguindo as metodologias **Spec Driven Development (SDD)** e **Test Driven Development (TDD)**.

O objetivo é duplo: produzir um sistema funcional e seguro, e documentar o processo de desenvolvimento orientado por testes para fins didáticos.

> **Regra central:** nenhuma linha de código de produção é escrita sem um teste falhando antes.
>
> Ciclo obrigatório: 🔴 RED → 🟢 GREEN → ♻️ REFACTOR

---

## Proposta

A maioria dos tutoriais de autenticação começa pelo código. Este projeto inverte a ordem:

1. **Spec** — descreve o comportamento esperado em linguagem natural e contrato de API
2. **Teste** — traduz a spec para código de teste (que falha)
3. **Implementação** — escreve o mínimo para o teste passar
4. **Refactor** — melhora o código sem quebrar nenhum teste

O resultado é um servidor OAuth2 completo (Authorization Code + PKCE, Refresh Token, Revogação) com cobertura de testes de 85 %+, desenvolvido camada por camada de forma rastreável.

---

## Stack

| Camada | Tecnologia | Versão |
|---|---|---|
| Runtime | Python | 3.10+ |
| Framework | FastAPI | 0.115 |
| Validação | Pydantic v2 | 2.10 |
| ORM | SQLAlchemy (async) | 2.0 |
| Banco (dev) | SQLite + aiosqlite | — |
| Tokens | python-jose + passlib/bcrypt | — |
| Testes | pytest + pytest-asyncio + httpx | — |
| Coverage | pytest-cov | — |
| Rate limit | slowapi | — |

---

## Módulos implementados

| # | Módulo | Endpoint(s) | Status |
|---|---|---|---|
| M1 | Registro de usuário | `POST /auth/register` | ✅ |
| M2 | Login (JWT interno) | `POST /auth/login` | ✅ |
| M3 | OAuth2 — Authorization Code | `GET /oauth/authorize` | ✅ |
| M4 | OAuth2 — Token Exchange + PKCE | `POST /oauth/token` | ✅ |
| M5 | Refresh Token (rotacionado) | `POST /oauth/token` | ✅ |
| M6 | Rotas protegidas e scopes | `GET /users/me` | ✅ |
| M7 | Revogação de tokens (RFC 7009) | `POST /oauth/revoke` | ✅ |

---

## Fluxo OAuth2 implementado

```
1. App gera  code_verifier  (string aleatória segura)
2. App calcula  code_challenge = base64url(sha256(code_verifier))
3. Redirect →  GET /oauth/authorize?response_type=code
                               &client_id=...
                               &redirect_uri=...
                               &scope=...
                               &state=...
                               &code_challenge=...
                               &code_challenge_method=S256
4. Servidor autentica o usuário e gera um  authorization_code
5. Redirect de volta →  GET <redirect_uri>?code=...&state=...
6. App troca o código →  POST /oauth/token
                              grant_type=authorization_code
                              code=...
                              code_verifier=...   ← PKCE
                              client_id + client_secret
7. Servidor verifica: sha256(code_verifier) == code_challenge
8. Servidor retorna  access_token  +  refresh_token
9. App usa o token →  Authorization: Bearer <access_token>
```

---

## Setup do ambiente

### 1. Clonar o repositório

```bash
git clone https://github.com/enzoblousa/AuthTDD.git
cd AuthTDD
```

### 2. Criar o ambiente virtual

```bash
# Usando virtualenv (recomendado se python3-venv não estiver disponível)
virtualenv -p python3 .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
```

### 3. Instalar dependências

```bash
# Dependências de desenvolvimento (inclui as de produção)
pip install -r requirements-dev.txt
```

### 4. Configurar variáveis de ambiente

```bash
cp .env.example .env
```

Edite o `.env` gerado:

```env
# Gere uma chave segura com:
# python -c "import secrets; print(secrets.token_urlsafe(64))"
SECRET_KEY=troque-por-uma-chave-longa-e-aleatoria

ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
AUTH_CODE_EXPIRE_MINUTES=10
REFRESH_TOKEN_EXPIRE_DAYS=30

# SQLite para desenvolvimento local
DATABASE_URL=sqlite+aiosqlite:///./auth.db
```

---

## Rodando o servidor

```bash
uvicorn app.main:app --reload
```

O servidor sobe em `http://localhost:8000`.

### Endpoints de documentação (gerados automaticamente pelo FastAPI)

| URL | Descrição |
|---|---|
| `http://localhost:8000/docs` | Swagger UI interativo |
| `http://localhost:8000/redoc` | ReDoc (documentação alternativa) |
| `http://localhost:8000/openapi.json` | Schema OpenAPI 3.1 em JSON |
| `http://localhost:8000/health` | Health check |

---

## Comandos de teste

```bash
# Rodar todos os testes
pytest

# Com output verboso
pytest -v

# Parar no primeiro erro
pytest -x

# Apenas testes unitários
pytest tests/unit/ -v

# Apenas testes de integração
pytest tests/integration/ -v

# Apenas testes end-to-end
pytest tests/e2e/ -v

# Coverage com resumo no terminal
pytest --cov=app --cov-report=term-missing

# Coverage com relatório HTML (abre em htmlcov/index.html)
pytest --cov=app --cov-report=html

# Rodar um teste específico
pytest tests/integration/test_oauth_flow.py::test_authorization_code_success -v

# Rodar todos os testes de um arquivo
pytest tests/integration/test_oauth_flow.py -v
```

---

## Estrutura do projeto

```
auth-tdd/
├── app/
│   ├── main.py                  # Entry point FastAPI
│   ├── config.py                # Configurações (pydantic-settings)
│   ├── database.py              # Engine, session, base
│   ├── models/                  # SQLAlchemy models (tabelas)
│   │   ├── user.py
│   │   ├── oauth_client.py
│   │   └── token.py
│   ├── schemas/                 # Pydantic schemas (contratos da API)
│   │   ├── user.py
│   │   ├── oauth.py
│   │   └── token.py
│   ├── routers/                 # Endpoints organizados por domínio
│   │   ├── auth.py              # /auth/register, /auth/login
│   │   ├── oauth.py             # /oauth/authorize, /oauth/token, /oauth/revoke
│   │   └── users.py             # /users/me
│   ├── services/                # Lógica de negócio (testável isoladamente)
│   │   ├── auth_service.py
│   │   ├── token_service.py
│   │   └── oauth_service.py
│   └── core/                    # Utilitários centrais
│       ├── security.py          # Hash de senha, JWT
│       ├── dependencies.py      # FastAPI Depends (get_current_user etc.)
│       └── exceptions.py        # HTTP exceptions customizadas
│
├── tests/
│   ├── conftest.py              # Fixtures globais
│   ├── unit/                    # Testes unitários (sem I/O)
│   ├── integration/             # Testes de endpoints (banco em memória)
│   └── e2e/                     # Fluxo OAuth2 completo
│
├── specs/                       # Especificações escritas antes do código
│   ├── 01_user_registration.md
│   ├── 02_login.md
│   ├── 03_oauth_authorize.md
│   ├── 04_oauth_token.md
│   ├── 05_token_refresh.md
│   ├── 06_protected_routes.md
│   └── 07_revocation.md
│
├── .env.example
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## Segurança

- Senhas armazenadas com **bcrypt** (fator de custo 12)
- JWT assinado com **HS256** — segredo via variável de ambiente, nunca hardcoded
- **PKCE obrigatório** em todos os fluxos Authorization Code
- Authorization codes são **one-time use** e expiram em 10 minutos
- **Refresh tokens rotacionados** a cada uso
- **Revogação em cascata** — revogar um refresh token invalida todos os access tokens derivados
- Rate limiting nos endpoints de autenticação via **slowapi**
- Proteção contra timing attacks nas comparações de credenciais (`secrets.compare_digest`)

---

## Referências

### RFCs

- [RFC 6749 — OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)

### Documentação das bibliotecas

- [FastAPI — Documentação oficial](https://fastapi.tiangolo.com/)
- [FastAPI — Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Pydantic v2](https://docs.pydantic.dev/latest/)
- [SQLAlchemy 2.0 (async)](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
- [pytest](https://docs.pytest.org/en/stable/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/en/latest/)

### Metodologias

- [Test-Driven Development by Example — Kent Beck](https://www.oreilly.com/library/view/test-driven-development/0321146530/)
- [Growing Object-Oriented Software, Guided by Tests — Freeman & Pryce](https://www.oreilly.com/library/view/growing-object-oriented-software/9780321574442/)

### Repositório

- [github.com/enzoblousa/AuthTDD](https://github.com/enzoblousa/AuthTDD)
