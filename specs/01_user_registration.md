# Spec M1 — Registro de usuário

**Status:** `[x] Spec` → `[x] Testes escritos` → `[x] Implementado` → `[ ] Revisado`

---

## Caso de uso

Um visitante sem conta fornece nome, e-mail e senha para criar uma nova conta no sistema. Após o registro bem-sucedido, a conta já está ativa e o usuário pode fazer login.

---

## Regras de negócio

1. O e-mail deve ser único no sistema — não podem existir dois usuários com o mesmo e-mail.
2. O e-mail deve ter formato válido (RFC 5322 simplificado).
3. A senha deve ter no mínimo 8 caracteres, ao menos 1 letra maiúscula, 1 letra minúscula e 1 número.
4. A senha **nunca** deve ser armazenada em texto plano — usar bcrypt com fator de custo 12.
5. A resposta **nunca** deve incluir a senha ou o hash da senha.
6. O campo `name` é obrigatório e deve ter entre 2 e 100 caracteres.

---

## Contrato da API

### Request

```
POST /auth/register
Content-Type: application/json
```

```json
{
  "name": "João Silva",
  "email": "joao@exemplo.com",
  "password": "Senha1234"
}
```

### Responses

**201 Created — Registro bem-sucedido**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "João Silva",
  "email": "joao@exemplo.com",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**400 Bad Request — E-mail já cadastrado**

```json
{
  "detail": "Email already registered"
}
```

**422 Unprocessable Entity — Validação de campos**

```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

---

## Schema Pydantic

```python
# schemas/user.py

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator("password")
    def password_strength(cls, v):
        # Deve conter ao menos: 1 maiúscula, 1 minúscula, 1 número
        ...

class UserResponse(BaseModel):
    id: UUID
    name: str
    email: EmailStr
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
```

---

## Modelo de dados

```python
# models/user.py

class User(Base):
    __tablename__ = "users"

    id: UUID (primary key, default uuid4)
    name: str
    email: str (unique, indexed)
    hashed_password: str
    is_active: bool (default True)
    created_at: datetime (default utcnow)
    updated_at: datetime (auto-update)
```

---

## Casos de teste

### Testes unitários — `tests/unit/test_auth_service.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| U1 | Senha é hasheada antes de salvar | senha plain text | hash bcrypt no banco |
| U2 | Hash nunca é igual ao texto original | "Senha1234" | `verify("Senha1234", hash)` → True, mas `hash != "Senha1234"` |
| U3 | Validação de força de senha — fraca | "abc" | ValidationError |
| U4 | Validação de força de senha — sem maiúscula | "senha1234" | ValidationError |
| U5 | Validação de força de senha — sem número | "SenhaForte" | ValidationError |
| U6 | Validação de força de senha — válida | "Senha1234" | sem erro |

### Testes de integração — `tests/integration/test_register.py`

| # | Teste | Entrada | Esperado |
|---|-------|---------|----------|
| I1 | Registro com dados válidos | payload completo válido | 201, body com id/email/name |
| I2 | Resposta não contém senha | payload válido | campo "password" ausente na resposta |
| I3 | E-mail duplicado | mesmo e-mail duas vezes | segundo request → 400 |
| I4 | E-mail com formato inválido | "nao-e-email" | 422 |
| I5 | Senha muito curta | password: "Ab1" | 422 |
| I6 | Senha sem maiúscula | password: "senha1234" | 422 |
| I7 | Senha sem número | password: "SenhaForte" | 422 |
| I8 | Nome ausente | sem campo name | 422 |
| I9 | Nome muito curto | name: "A" | 422 |
| I10 | Body vazio | `{}` | 422 |
| I11 | Usuário criado com is_active=True | payload válido | is_active: true na resposta |

---

## Dependências

- Nenhuma. Este é o primeiro módulo — sem dependências de outros módulos.

## Desbloqueado por este módulo

- M2 (Login) — precisa de usuários existentes para autenticar
