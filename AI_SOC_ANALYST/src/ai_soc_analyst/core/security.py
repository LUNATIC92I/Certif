"""Primitives de sécurité : mot de passe local, noms de fichiers sûrs, contrôle de chemins."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

_ITER = 390_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITER)
    return f"pbkdf2_sha256${_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


_UNSAFE = re.compile(r"[^A-Za-z0-9._\- ]+")


def safe_filename(name: str, max_len: int = 120) -> str:
    """Nom de fichier neutre : sans séparateur, sans caractère de contrôle, sans nom réservé Windows."""
    base = PureWindowsPath(PurePosixPath(name).name).name
    base = _UNSAFE.sub("_", base).strip(" .") or "fichier"
    if base.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                      *(f"LPT{i}" for i in range(10))}:
        base = "_" + base
    return base[:max_len]


def is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def is_unsafe_archive_member(name: str) -> bool:
    """Détecte les membres d'archive dangereux (path traversal, chemins absolus, lecteurs)."""
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return True
    return any(part == ".." for part in n.split("/"))
