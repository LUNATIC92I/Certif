"""Analyse statique de fichiers suspects (PE). Aucun fichier n'est jamais exécuté."""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from ..core.logging_setup import get_logger
from ..core.paths import resource_dir

log = get_logger("static")

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": "Allocation mémoire dans un autre processus (injection)",
    "WriteProcessMemory": "Écriture dans la mémoire d'un autre processus (injection)",
    "CreateRemoteThread": "Création de thread distant (injection)",
    "NtUnmapViewOfSection": "Démappage de section (process hollowing)",
    "SetWindowsHookExA": "Hook clavier/souris (keylogging possible)",
    "SetWindowsHookExW": "Hook clavier/souris (keylogging possible)",
    "MiniDumpWriteDump": "Écriture de dump mémoire (vol d'identifiants possible)",
    "CryptEncrypt": "Chiffrement (CryptoAPI)",
    "URLDownloadToFileA": "Téléchargement de fichier",
    "URLDownloadToFileW": "Téléchargement de fichier",
    "IsDebuggerPresent": "Détection de débogueur (anti-analyse)",
    "AdjustTokenPrivileges": "Modification de privilèges du jeton",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def extract_strings(data: bytes, min_len: int = 6, limit: int = 4000) -> list[str]:
    ascii_s = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    out = [s.decode("ascii", "ignore") for s in ascii_s[:limit]]
    out += [s.decode("utf-16le", "ignore") for s in wide[:limit]]
    return out[:limit]


def _yara_rules():
    try:
        import yara  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    rules_dir = resource_dir() / "resources" / "yara"
    files = {p.stem: str(p) for p in rules_dir.glob("*.yar")} if rules_dir.exists() else {}
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception as exc:  # noqa: BLE001
        log.warning("Règles YARA non compilées : %s", exc)
        return None


def analyze_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> dict:
    data = path.open("rb").read(max_bytes)
    result: dict = {"entropy": round(shannon_entropy(data), 3), "size_analyzed": len(data), "pe": None,
                    "yara_matches": [], "indicators": [], "executed": False}
    if data[:2] == b"MZ":
        try:
            import pefile

            pe = pefile.PE(data=data, fast_load=False)
            sections = [{"name": s.Name.rstrip(b"\x00").decode("latin-1"), "entropy": round(s.get_entropy(), 3),
                         "raw_size": s.SizeOfRawData} for s in pe.sections]
            imports = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode("latin-1"))
            signed = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress) if len(
                pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else False
            result["pe"] = {
                "machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000), "sections": sections,
                "imports_count": len(imports), "has_authenticode_directory": signed,
                "imphash": pe.get_imphash() or "",
            }
            for name, why in SUSPICIOUS_IMPORTS.items():
                if name in imports:
                    result["indicators"].append(f"Import {name} : {why}")
            if any(s["entropy"] > 7.2 for s in sections):
                result["indicators"].append("Section à entropie élevée (> 7,2) : contenu compressé ou chiffré (packing possible)")
            if len(imports) < 10:
                result["indicators"].append("Très peu d'imports : résolution dynamique ou packer possible")
            if not signed:
                result["indicators"].append("Aucun répertoire de signature Authenticode")
            pe.close()
        except Exception as exc:  # noqa: BLE001
            result["indicators"].append(f"En-tête PE invalide ou corrompu : {exc}")
    rules = _yara_rules()
    if rules is not None:
        try:
            result["yara_matches"] = [m.rule for m in rules.match(data=data, timeout=30)]
        except Exception as exc:  # noqa: BLE001
            log.warning("YARA : %s", exc)
    strings = extract_strings(data, limit=2000)
    result["interesting_strings"] = [s for s in strings if re.search(
        r"(?i)(https?://|powershell|cmd\.exe|\\run\\|vssadmin|mimikatz|sekurlsa|bitcoin|\.onion|kms)", s)][:50]
    return result
