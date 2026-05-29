# auth-tdd

Sistema de Autenticação OAuth2 construído com **Spec Driven Development + Test Driven Development**.

> Regra central: nenhuma linha de código de produção sem um teste falhando antes.
> Ciclo: 🔴 RED → 🟢 GREEN → ♻️ REFACTOR

Stack: Python 3.10+ · FastAPI · Pydantic v2 · SQLAlchemy 2.0 (async) · pytest.

## Setup

O sistema não possui o pacote `python3-venv`; usamos `virtualenv`:

```bash
virtualenv -p python3 .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # ajuste SECRET_KEY etc.
```

## Testes

```bash
pytest                                   # tudo
pytest tests/unit/ -v                    # unitários
pytest --cov=app --cov-report=term-missing
```

## Servidor

```bash
uvicorn app.main:app --reload
# OpenAPI em http://localhost:8000/docs
```

## Progresso dos módulos

| Módulo | Descrição | Status |
|--------|-----------|--------|
| M1 | Registro de usuário | ✅ Implementado (21 testes verdes) |
| M2 | Login (JWT) | ⏳ Pendente |
| M3 | OAuth2 Authorize | ⏳ Pendente |
| M4 | OAuth2 Token Exchange | ⏳ Pendente |
| M5 | Refresh Token | ⏳ Pendente |
| M6 | Rotas protegidas / scopes | ⏳ Pendente |
| M7 | Revogação | ⏳ Pendente |
