"""Testes unitários do módulo de segurança (hash de senha).

Cobre a essência de U1/U2 da spec M1: a senha nunca é guardada em texto
plano e o hash gerado é verificável.
"""

from app.core.security import hash_password, verify_password


def test_hash_password_is_not_plaintext():
    # Arrange / Act
    hashed = hash_password("Senha1234")

    # Assert — bcrypt nunca produz o texto original
    assert hashed != "Senha1234"
    assert hashed.startswith("$2")  # prefixo de hash bcrypt


def test_verify_password_with_correct_password_returns_true():
    hashed = hash_password("Senha1234")
    assert verify_password("Senha1234", hashed) is True


def test_verify_password_with_wrong_password_returns_false():
    hashed = hash_password("Senha1234")
    assert verify_password("SenhaErrada9", hashed) is False


def test_two_hashes_of_same_password_differ():
    # bcrypt usa salt aleatório → hashes diferentes para a mesma senha
    assert hash_password("Senha1234") != hash_password("Senha1234")
