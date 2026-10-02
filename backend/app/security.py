"""Password hashing helpers.

Argon2id via ``pwdlib`` (the hashing library recommended by FastAPI). Only the
derived hash is ever stored; plaintext passwords never reach the database.
"""
from pwdlib import PasswordHash

_password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Return an Argon2id hash for ``password``."""
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Check ``password`` against a stored hash, tolerating missing/invalid hashes."""
    if not password_hash:
        return False
    try:
        return _password_hash.verify(password, password_hash)
    except Exception:
        # A corrupted/unknown hash must fail closed, never raise a 500.
        return False
