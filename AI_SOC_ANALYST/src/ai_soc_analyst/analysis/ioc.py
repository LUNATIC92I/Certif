"""Extraction et qualification des indicateurs (IOC).

Principe : un IOC extrait n'est jamais présumé malveillant. Son niveau de risque n'est relevé que s'il est
directement lié à une détection comportementale (finding) ou à une réponse de réputation réelle.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from ..ingestion.models import NormalizedEvent
from .results import Finding, IOCRecord

_REFANG = [(re.compile(r"hxxp", re.I), "http"), (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
           (re.compile(r"\[:\]"), ":"), (re.compile(r"\[at\]|\(at\)", re.I), "@")]
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`|\\^{}]+", re.I)
RE_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
RE_IPV6 = re.compile(r"(?<![:\w])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![:\w])", re.I)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
RE_SHA256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
RE_SHA1 = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
RE_MD5 = re.compile(r"(?<![0-9a-f-])[0-9a-f]{32}(?![0-9a-f-])", re.I)
RE_WINPATH = re.compile(r"(?:[A-Za-z]:\\|\\\\[\w.$-]+\\|%[A-Za-z]+%\\)[^\s\"'<>|*?\r\n]+?\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|hta|scr|"
                        r"msi|lnk|iso|img|sys|zip|rar|7z|docm|xlsm|jar|py|tmp|dat)\b", re.I)
RE_REG = re.compile(r"\b(?:HKLM|HKCU|HKU|HKCR|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT)"
                    r"(?:\\[^\s\"'\r\n\\]+)+", re.I)

FILE_EXT_TLDS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr", "msi", "lnk", "iso", "img", "sys",
                 "zip", "rar", "txt", "log", "tmp", "dat", "ini", "cfg", "xml", "json", "csv", "doc", "docx",
                 "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "png", "jpg", "gif", "jpeg", "evtx", "eml",
                 "msg", "py", "jar", "sh", "conf", "yaml", "yml", "ps", "db", "bak", "old", "local", "lan",
                 "internal", "corp", "intra", "home", "localdomain", "dllx", "manifest", "config", "mui", "cpl",
                 "ocx", "drv", "inf", "cab", "evt", "etl", "html", "htm", "aspx", "php", "asp", "css", "md", "dmp"}
BENIGN_DOMAINS = ("microsoft.com", "windowsupdate.com", "windows.com", "office.com", "office365.com", "live.com",
                  "msftncsi.com", "digicert.com", "verisign.com", "w3.org", "schemas.microsoft.com",
                  "xmlsoap.org", "openxmlformats.org", "purl.org", "google.com", "gstatic.com", "apple.com",
                  "mozilla.org", "ubuntu.com", "akamaitechnologies.com")
PROCESS_FIELDS = ("process_name", "parent_name")
SYSTEM_PATH = re.compile(r"(?i)^[a-z]:\\(windows\\(system32|syswow64|winsxs)|program files( \(x86\))?)\\")
EXEC_EXT = re.compile(r"(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|jse|hta|scr|msi|lnk|iso|img|sys|jar|py|sh|com|cpl|ocx|wsf|"
                      r"docm|xlsm|pptm|one)$")
# TLD génériques reconnus (les ccTLD à 2 lettres sont acceptés) – évite les faux domaines tels que « Net.WebClient »
GTLDS = set("""com net org info biz io co ai app dev xyz top site online club shop store tech cloud live me tv cc
pro name mobi asia tel travel jobs museum aero coop edu gov mil int arpa page link click space website host press
fun icu vip work life world today news blog email solutions services support network systems digital agency media
group company global center zone tools software security systems technology ltd llc inc gmbh africa capital city
download stream win bid loan men date party review trade science webcam racing cricket accountant faith gq ml cf
ga tk su ws am fm la ly me to wtf lol rocks guru ninja expert team best bar cafe chat social direct business
example test invalid localhost onion amazon google microsoft windows apple""".split())
RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def classify_ip(value: str) -> tuple[str, str] | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    kind = "ipv6" if ip.version == 6 else "ipv4"
    if ip.version == 4 and any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
        return kind, "documentation (RFC 5737)"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return kind, "technique"
    if ip.is_private or ip.is_reserved or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")):
        return kind, "interne"
    return kind, "publique"


def _valid_domain(d: str) -> bool:
    d = d.lower().strip(".")
    tld = d.rsplit(".", 1)[-1]
    if tld in FILE_EXT_TLDS or tld.isdigit() or len(d) > 253:
        return False
    if len(tld) != 2 and tld not in GTLDS and not tld.startswith("xn--"):
        return False
    labels = d.split(".")
    if len(labels) < 2 or any(not lbl for lbl in labels):
        return False
    if any(lbl in FILE_EXT_TLDS for lbl in labels[1:]):  # ex. document.xlsx.lockdsim
        return False
    return not re.fullmatch(r"[\d.]+", d)


def extract_from_text(text: str) -> list[tuple[str, str]]:
    text = refang(text)
    found: list[tuple[str, str]] = []
    urls = RE_URL.findall(text)
    for u in urls:
        found.append(("url", u.rstrip(".,;)]")))
    for m in RE_EMAIL.findall(text):
        found.append(("email", m.lower()))
    stripped = RE_URL.sub(" ", text)
    stripped_no_mail = RE_EMAIL.sub(" ", stripped)
    for h in RE_SHA256.findall(text):
        found.append(("sha256", h.lower()))
    no256 = RE_SHA256.sub(" ", text)
    for h in RE_SHA1.findall(no256):
        found.append(("sha1", h.lower()))
    no160 = RE_SHA1.sub(" ", no256)
    for h in RE_MD5.findall(no160):
        if not re.fullmatch(r"0+|f+", h.lower()):
            found.append(("md5", h.lower()))
    for ip in RE_IPV4.findall(text):
        found.append(("ipv4", ip))
    for ip in RE_IPV6.findall(text):
        if ip.count(":") >= 2 and classify_ip(ip):
            found.append(("ipv6", ip.lower()))
    for p in RE_WINPATH.findall(text):
        found.append(("file_path", p))
    for r in RE_REG.findall(text):
        found.append(("registry_key", r.rstrip(".,;")))
    path_free = RE_WINPATH.sub(" ", stripped_no_mail)
    path_free = RE_REG.sub(" ", path_free)
    path_free = re.sub(r"\S*[\\/]\S*", " ", path_free)  # jetons contenant un séparateur de chemin
    for d in RE_DOMAIN.findall(path_free):
        if _valid_domain(d):
            found.append(("domain", d.lower()))
    for u in urls:
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0].lower()
        if host and not RE_IPV4.fullmatch(host) and _valid_domain(host):
            found.append(("domain", host))
    return found


def extract_iocs(events: list[NormalizedEvent], findings: list[Finding]) -> list[IOCRecord]:
    occurrences: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add(kind: str, value: str, evid: str) -> None:
        value = value.strip().strip('"').strip("'")
        if value and len(value) < 2000:
            occurrences[(kind, value)].add(evid)

    for ev in events:
        for kind, value in extract_from_text(ev.text_blob()):
            add(kind, value, ev.evidence_id)
        for kind, attr in (("sha256", "sha256"), ("sha1", "sha1"), ("md5", "md5")):
            if getattr(ev, attr):
                add(kind, getattr(ev, attr), ev.evidence_id)
        for attr in PROCESS_FIELDS:
            v = getattr(ev, attr)
            if v and re.search(r"\.\w{2,4}$", v):
                add("process_name", v.lower(), ev.evidence_id)
        for attr in ("process_path", "parent_path", "target_file", "image_loaded"):
            v = getattr(ev, attr)
            if attr == "target_file" and not EXEC_EXT.search(v or ""):
                continue  # fichiers de données modifiés (ex. fichiers chiffrés) : preuves d'impact, pas des IOC
            if v and re.match(r"^(?:[A-Za-z]:\\|\\\\|/)", v):
                add("file_path", v, ev.evidence_id)
        if ev.target_file and EXEC_EXT.search(ev.target_file):
            add("file_name", re.split(r"[\\/]", ev.target_file)[-1], ev.evidence_id)
        for a in ev.attachments:
            add("file_name", a, ev.evidence_id)
        for attr in ("user", "target_user"):
            v = getattr(ev, attr)
            if v and v.lower() not in ("system", "-", "n/a", "nt authority\\system", "local service", "network service"):
                add("user_account", v, ev.evidence_id)
        if ev.registry_key:
            add("registry_key", ev.registry_key, ev.evidence_id)
        if ev.dns_query and _valid_domain(ev.dns_query):
            add("domain", ev.dns_query.lower().rstrip("."), ev.evidence_id)
        for ipf in ("src_ip", "dst_ip"):
            v = getattr(ev, ipf)
            if v:
                c = classify_ip(v)
                if c:
                    add(c[0], v.lower(), ev.evidence_id)

    # contenu décodé par les règles (ex. PowerShell -EncodedCommand) : rattaché à l'événement d'origine
    for f in findings:
        decoded = f.details.get("decoded")
        if decoded:
            for kind, value in extract_from_text(decoded):
                for evid in f.evidence_ids[:1]:
                    add(kind, value, evid)
            f.details.setdefault("ioc_values", [])
            f.details["ioc_values"] = list(f.details["ioc_values"]) + [v for _, v in extract_from_text(decoded)]

    # lien IOC <-> findings : uniquement si l'événement justifiant la finding contient l'IOC
    ev_by_id = {e.evidence_id: e for e in events}
    finding_links: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.status == "False Positive":
            continue
        involved = set(f.details.get("ioc_values", []))
        for evid in f.evidence_ids:
            ev = ev_by_id.get(evid)
            if ev:
                blob = ev.text_blob().lower() + " " + " ".join(
                    (ev.process_name, ev.parent_name, ev.user, ev.sha256, ev.md5, ev.sha1)).lower()
                involved |= {v for (k, v) in occurrences if v.lower() in blob}
        for (k, v) in occurrences:
            if v in involved:
                finding_links[(k, v)].append(f)

    # Hashs de binaires légitimes situés dans des emplacements système (souvent détournés : LOLBins)
    system_hashes: dict[str, str] = {}
    system_paths: set[str] = set()
    system_names: set[str] = set()
    for ev in events:
        path = ev.process_path or ""
        if SYSTEM_PATH.match(path) and not re.search(r"(?i)\\(temp|tmp)\\", path):
            for h in (ev.sha256, ev.sha1, ev.md5):
                if h:
                    system_hashes[h.lower()] = ev.process_name or path
            system_paths.add(path.lower())
            if ev.process_name:
                system_names.add(ev.process_name.lower())
        for ppath, pname in ((ev.parent_path or "", ev.parent_name or ""),):
            if SYSTEM_PATH.match(ppath):
                system_paths.add(ppath.lower())
                if pname:
                    system_names.add(pname.lower())

    recipients = {a.lower() for ev in events for a in RE_EMAIL.findall(ev.email_to or "")}
    # propagation : hash d'un processus dont le chemin est lié à une détection
    hashes_by_path: dict[str, set[str]] = defaultdict(set)
    for ev in events:
        for h in (ev.sha256, ev.sha1, ev.md5):
            if h and ev.process_path:
                hashes_by_path[ev.process_path.lower()].add(h.lower())

    records: list[IOCRecord] = []
    sev_to_risk = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Info"}
    for (kind, value), evids in occurrences.items():
        rec = IOCRecord(value=value, ioc_type=kind, occurrences=len(evids), evidence_ids=sorted(evids)[:50],
                        source="Extraction locale depuis les preuves importées")
        if kind in ("ipv4", "ipv6"):
            scope = classify_ip(value)[1]  # type: ignore[index]
            rec.justification = f"Adresse {scope}."
            if scope in ("interne", "technique", "documentation (RFC 5737)"):
                rec.reputation = "Non applicable (adresse non routable publiquement)" if scope != "documentation (RFC 5737)" \
                    else "Non vérifiée (plage de documentation)"
        if kind == "domain" and any(value == d or value.endswith("." + d) for d in BENIGN_DOMAINS):
            rec.justification = "Domaine d'éditeur connu (liste locale de domaines courants) : faible intérêt a priori."
        linked = finding_links.get((kind, value), [])
        if kind in ("sha256", "sha1", "md5") and value.lower() in system_hashes:
            rec.risk = "Info"
            rec.validation_status = "Binaire système légitime"
            rec.justification = (f"Hash du binaire {system_hashes[value.lower()]} situé dans un répertoire système : outil "
                                 "légitime potentiellement détourné. Ne pas bloquer ce hash ; traiter le comportement.")
        elif kind in ("ipv4", "ipv6") and classify_ip(value) and classify_ip(value)[1] in ("interne", "technique"):
            rec.risk = "Info"
            rec.validation_status = "Actif interne impliqué" if linked else "Adresse interne"
            rec.justification += (" Hôte ou service interne présent dans les événements de "
                                  + ", ".join(sorted({f.finding_id for f in linked})) + " (périmètre, pas un indicateur "
                                  "de l'attaquant)." if linked else "")
        elif kind == "email" and value.lower() in recipients:
            rec.risk = "Info"
            rec.validation_status = "Destinataire (victime potentielle)"
            rec.justification = "Adresse destinataire du message analysé : pas un indicateur de l'attaquant."
        elif (kind == "file_path" and (value.lower() in system_paths or SYSTEM_PATH.match(value))) or \
                (kind == "process_name" and value.lower() in system_names):
            rec.risk = "Info"
            rec.validation_status = "Binaire système légitime"
            rec.justification = ("Binaire légitime situé dans un répertoire système"
                                 + (", utilisé dans : " + ", ".join(sorted({f.finding_id for f in linked})) if linked else "")
                                 + ". L'outil est détourné : surveiller l'usage, ne pas le bloquer globalement.")
        elif linked:
            top = max(linked, key=lambda f: (RISK_ORDER.get(sev_to_risk.get(f.severity, "Info"), 0), f.confidence))
            rec.risk = sev_to_risk.get(top.severity, "Low") if top.status in ("Confirmed", "Likely") else "Medium" \
                if RISK_ORDER.get(sev_to_risk.get(top.severity, "Info"), 0) >= 2 else "Low"
            rec.validation_status = "Lié à une détection comportementale" if top.status != "Confirmed" \
                else "Validé par preuve locale (détection confirmée)"
            rec.justification = (rec.justification + " " if rec.justification else "") + \
                "Apparaît dans les événements de : " + ", ".join(sorted({f.finding_id + ' ' + f.title for f in linked})[:4]) + "."
        elif not rec.justification:
            rec.justification = "Extrait des données ; aucune détection comportementale associée."
        records.append(rec)
    by_value = {(r.ioc_type, r.value.lower()): r for r in records}
    for r in records:
        if r.ioc_type == "file_path" and RISK_ORDER.get(r.risk, 0) >= 2 and r.validation_status != "Binaire système légitime":
            for h in hashes_by_path.get(r.value.lower(), ()):
                for kind in ("sha256", "sha1", "md5"):
                    hr = by_value.get((kind, h))
                    if hr and hr.validation_status != "Binaire système légitime" and RISK_ORDER[hr.risk] < RISK_ORDER[r.risk]:
                        hr.risk = r.risk
                        hr.validation_status = r.validation_status
                        hr.justification += f" Hash du fichier {r.value} (même niveau de risque que le processus)."
    type_order = {t: i for i, t in enumerate(("sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url", "file_path",
                                               "file_name", "process_name", "registry_key", "email", "user_account"))}
    records.sort(key=lambda r: (-RISK_ORDER.get(r.risk, 0), type_order.get(r.ioc_type, 99), r.value))
    return records
