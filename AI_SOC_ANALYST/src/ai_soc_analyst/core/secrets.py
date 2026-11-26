"""Stockage chiffré des secrets (clés API).

Les secrets sont chiffrés avec Fernet (AES-128-CBC + HMAC-SHA256). La clé maître est :
- sous Windows : protégée par DPAPI (CryptProtectData, liée au compte utilisateur) ;
- ailleurs : stockée dans un fichier aux permissions 0600.
Les valeurs ne sont jamais écrites en clair sur disque ni dans les journaux.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .logging_setup import get_logger

log = get_logger("secrets")


def _dpapi(data: bytes, protect: bool) -> bytes:  # pragma: no cover - Windows uniquement
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = BLOB()
    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI a échoué")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


class SecretStore:
    def __init__(self, secrets_file: Path, key_file: Path):
        self.secrets_file = secrets_file
        self.key_file = key_file
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        windows = sys.platform.startswith("win")
        if self.key_file.exists():
            raw = self.key_file.read_bytes()
            return _dpapi(raw, protect=False) if windows else raw
        key = Fernet.generate_key()
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        payload = _dpapi(key, protect=True) if windows else key
        self.key_file.write_bytes(payload)
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass
        return key

    def _read_all(self) -> dict[str, str]:
        if not self.secrets_file.exists():
            return {}
        try:
            return json.loads(self._fernet.decrypt(self.secrets_file.read_bytes()).decode("utf-8"))
        except (InvalidToken, ValueError):
            log.error("Fichier de secrets illisible (clé différente ou fichier corrompu) : secrets ignorés")
            return {}

    def _write_all(self, data: dict[str, str]) -> None:
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.secrets_file.with_suffix(".tmp")
        tmp.write_bytes(self._fernet.encrypt(json.dumps(data).encode("utf-8")))
        os.replace(tmp, self.secrets_file)
        try:
            os.chmod(self.secrets_file, 0o600)
        except OSError:
            pass

    def get(self, name: str) -> str | None:
        value = self._read_all().get(name)
        return value or None

    def set(self, name: str, value: str | None) -> None:
        data = self._read_all()
        if value:
            data[name] = value
        else:
            data.pop(name, None)
        self._write_all(data)

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def names(self) -> list[str]:
        return sorted(self._read_all())
