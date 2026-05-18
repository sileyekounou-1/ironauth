import pytest
from ironauth.core.password import PasswordManager


def test_hash_and_verify():
    pm = PasswordManager()
    hashed = pm.hash("MonMotDePasse123!")
    assert pm.verify("MonMotDePasse123!", hashed)
    assert not pm.verify("mauvais_mdp", hashed)


def test_hash_is_unique():
    pm = PasswordManager()
    h1 = pm.hash("MonMotDePasse123!")
    h2 = pm.hash("MonMotDePasse123!")
    assert h1 != h2  # Argon2 salt aléatoire


def test_validate_strength_ok():
    pm = PasswordManager()
    pm.validate_strength("MonMotDePasse123!")  # Ne doit pas lever d'exception


def test_validate_strength_trop_court():
    pm = PasswordManager()
    with pytest.raises(ValueError, match="12 caractères"):
        pm.validate_strength("Court1!")


def test_validate_strength_sans_majuscule():
    pm = PasswordManager()
    with pytest.raises(ValueError, match="majuscule"):
        pm.validate_strength("monmotdepasse123!")


def test_validate_strength_sans_chiffre():
    pm = PasswordManager()
    with pytest.raises(ValueError, match="chiffre"):
        pm.validate_strength("MonMotDePasse!!!")


def test_validate_strength_sans_special():
    pm = PasswordManager()
    with pytest.raises(ValueError, match="spécial"):
        pm.validate_strength("MonMotDePasse123")


def test_generate_reset_token():
    pm = PasswordManager()
    t1 = pm.generate_reset_token()
    t2 = pm.generate_reset_token()
    assert t1 != t2
    assert len(t1) > 20
