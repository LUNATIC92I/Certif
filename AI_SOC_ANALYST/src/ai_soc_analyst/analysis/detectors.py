"""Règles de détection comportementale (moteur déterministe local).

Chaque règle :
- ne s'appuie que sur des champs présents dans les événements ;
- renvoie des findings citant les evidence_id exacts ;
- n'associe une technique MITRE que lorsque le comportement correspondant est observé
  (jamais sur la seule base d'un nom de fichier) ;
- qualifie le résultat (Confirmed / Likely / Suspicious) et un niveau de confiance explicite.
"""
from __future__ import annotations

import base64
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Callable, Iterable

from ..ingestion.models import NormalizedEvent
from .ioc import classify_ip
from .results import Finding

USER_WRITABLE = re.compile(r"(?i)\\(appdata|temp|tmp|users\\public|programdata|downloads|desktop|\$recycle\.bin|"
                           r"perflogs|windows\\temp)\\")
SYSTEM_DIR = re.compile(r"(?i)^[a-z]:\\(windows\\(system32|syswow64|winsxs)|program files( \(x86\))?)\\")
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
          "visio.exe"}
MGMT_AGENTS = {"ccmexec.exe", "ccmsetup.exe", "intunemanagementextension.exe", "agentexecutor.exe",
               "taniumclient.exe", "besclient.exe", "ltsvc.exe", "kaseya.exe", "pdqdeployrunner.exe",
               "senseir.exe", "gpscript.exe", "monitoringhost.exe"}
MGMT_PATHS = re.compile(r"(?i)\\windows\\ccm\\|\\windows\\ccmcache\\|microsoft intune management extension|"
                        r"\\imecache\\|\\tanium\\|\\bigfix enterprise\\|\\windows\\sysvol\\|\\netlogon\\")
KMS_TOKENS = ("kmspico", "kmsauto", "autokms", "autopico", "kms-r@1n", "kmsss.exe", "secoh-qad", "kmseldi",
              "kms_vl_all", "kmsconnectionbroker", "kms_service", "kmsactivator", "kms tools", "kmsnano",
              "aact.exe", "kmsauto net", "w10 digital activation", "hwidgen")


def _lc(s: str) -> str:
    return (s or "").lower()


def _ev_ids(events: Iterable[NormalizedEvent]) -> list[str]:
    return sorted({e.evidence_id for e in events})


def _mgmt_context(ev: NormalizedEvent) -> str:
    if _lc(ev.parent_name) in MGMT_AGENTS:
        return f"processus parent d'administration connu ({ev.parent_name})"
    blob = " ".join((ev.process_path, ev.command_line, ev.parent_path, ev.parent_command_line))
    if MGMT_PATHS.search(blob):
        return "chemin d'outil de gestion de parc (SCCM/Intune/GPO)"
    return ""


def decode_powershell(cmd: str) -> str:
    m = re.search(r"(?i)\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|"
                  r"encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", cmd or "")
    if not m:
        return ""
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        text = raw.decode("utf-16-le", errors="strict")
        return text if text.isprintable() or "\n" in text else text
    except Exception:  # noqa: BLE001
        return ""


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


class Ctx:
    def __init__(self, events: list[NormalizedEvent]):
        self.events = events
        self.by_type: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in events:
            self.by_type[e.event_type].append(e)
        self.procs = self.by_type["process_creation"]
        self.has_email = bool(self.by_type["email"])

    def cmd_events(self) -> list[NormalizedEvent]:
        """Événements porteurs d'une ligne de commande ou d'un bloc de script."""
        return [e for e in self.events if e.command_line or (e.event_type == "powershell_script" and e.message)]


def _f(rule: str, title: str, category: str, desc: str, sev: str, status: str, conf: float,
       evs: Iterable[NormalizedEvent], mitre: list[str], **details) -> Finding:
    evs = list(evs)
    benign = details.pop("benign_context", "")
    return Finding("", rule, title, category, desc, sev, status, round(conf, 2), _ev_ids(evs), mitre, details, benign)


# =============================================================== règles

def r_powershell(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.cmd_events():
        name = _lc(e.process_name)
        cmd = e.command_line or e.message
        low = _lc(cmd)
        if not (name in ("powershell.exe", "pwsh.exe") or "powershell" in low or e.event_type == "powershell_script"):
            continue
        decoded = decode_powershell(cmd)
        content = low + " " + decoded.lower()
        signals, mitre = [], ["T1059.001"]
        if decoded:
            signals.append("commande encodée en Base64 (décodée : « " + decoded[:200] + " »)")
            mitre.append("T1027.010")
        if re.search(r"(?i)(-w(indowstyle)?\s+h(idden)?\b|-nop\b|-noni\b|-noprofile|-executionpolicy\s+bypass|-ep\s+bypass)", cmd):
            signals.append("options de dissimulation/contournement (-w hidden, -nop, -ExecutionPolicy Bypass)")
        dl = re.search(r"(iex|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr |"
                       r"start-bitstransfer|invoke-restmethod|frombase64string)", content)
        if dl:
            signals.append(f"téléchargement ou exécution en mémoire ({dl.group(1)})")
            mitre.append("T1105")
        if not signals:
            continue
        benign = _mgmt_context(e)
        strong = bool(decoded) and bool(dl) or (bool(dl) and _lc(e.parent_name) in OFFICE)
        status = "Likely" if strong or len(signals) >= 2 else "Suspicious"
        conf = 0.8 if strong else (0.65 if len(signals) >= 2 else 0.45)
        if benign and not dl:
            status, conf = "Suspicious", 0.3
        out.append(_f("R-PS-001", "Exécution PowerShell suspecte", "Execution",
                      f"PowerShell lancé par {e.parent_name or 'un parent inconnu'} sur {e.host or 'hôte inconnu'} : "
                      + " ; ".join(signals) + ".", "High" if status == "Likely" else "Medium", status, conf, [e],
                      sorted(set(mitre)), decoded=decoded[:2000], benign_context=benign))
    return out


def r_office_child(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.procs:
        if _lc(e.parent_name) in OFFICE and _lc(e.process_name) in SCRIPT_HOSTS | {"wmiprvse.exe"}:
            mitre = ["T1204.002"]
            note = ""
            if ctx.has_email:
                mitre.append("T1566.001")
                note = " Un e-mail figure parmi les preuves : vecteur d'hameçonnage par pièce jointe probable."
            out.append(_f("R-OFF-001", "Application Office lançant un interpréteur", "Initial Access / Execution",
                          f"{e.parent_name} a lancé {e.process_name} ({(e.command_line or '')[:180]}). Une application "
                          f"bureautique ne lance normalement pas d'interpréteur : macro ou exploit probable.{note}",
                          "High", "Likely", 0.8, [e], mitre))
    return out


def r_lolbins(ctx: Ctx) -> list[Finding]:
    out = []
    checks: list[tuple[str, str, list[str], str]] = [
        ("certutil.exe", r"-urlcache|-split|-decode|verifyctl", ["T1105", "T1140"], "téléchargement/décodage via certutil"),
        ("mshta.exe", r"https?://|javascript:|vbscript:", ["T1218.005"], "exécution de contenu HTA distant via mshta"),
        ("regsvr32.exe", r"/i:https?|scrobj\.dll", ["T1218.010"], "chargement de scriptlet distant via regsvr32 (Squiblydoo)"),
        ("bitsadmin.exe", r"/transfer|/addfile", ["T1197", "T1105"], "transfert de fichier via BITS"),
        ("rundll32.exe", r"javascript:|\\(appdata|temp|users\\public|programdata|downloads)\\|,#?\d+\s*$",
         ["T1218.011"], "exécution de DLL hors emplacement système via rundll32"),
    ]
    for e in ctx.procs:
        name = _lc(e.process_name)
        for exe, pattern, mitre, label in checks:
            if name == exe and re.search(pattern, e.command_line or "", re.I):
                benign = _mgmt_context(e)
                out.append(_f("R-LOL-001", f"Utilisation détournée de {exe}", "Stealth / Execution",
                              f"{label} : {(e.command_line or '')[:220]}.", "Medium" if benign else "High",
                              "Suspicious" if benign else "Likely", 0.35 if benign else 0.75, [e], mitre,
                              benign_context=benign))
    return out


def r_user_writable_exec(ctx: Ctx) -> list[Finding]:
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in ctx.procs:
        if e.process_path and USER_WRITABLE.search(e.process_path) and e.process_path.lower().endswith((".exe", ".scr", ".com")):
            if re.search(r"(?i)\\(microsoft\\teams|microsoft\\onedrive|google\\chrome|zoom|slack|discord|"
                         r"programs\\microsoft vs code)\\", e.process_path):
                continue
            grouped[e.process_path.lower()].append(e)
    out = []
    for path, evs in grouped.items():
        e = evs[0]
        unsigned = any(x.signed is False for x in evs)
        out.append(_f("R-EXE-001", "Exécutable lancé depuis un répertoire accessible en écriture", "Execution",
                      f"{e.process_path} exécuté {len(evs)} fois (parent : {e.parent_name or 'inconnu'})"
                      + (", binaire non signé" if unsigned else "") + ". Emplacement fréquemment utilisé par les "
                      "charges malveillantes, mais aussi par certains logiciels légitimes : à qualifier.",
                      "Medium" if unsigned else "Low", "Suspicious", 0.45 if unsigned else 0.3, evs, [],
                      ioc_values=[e.process_path]))
    return out


def r_dll_sideloading(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.by_type["image_load"]:
        if not e.image_loaded or not e.process_path:
            continue
        pdir = e.process_path.rsplit("\\", 1)[0].lower()
        ddir = e.image_loaded.rsplit("\\", 1)[0].lower()
        if pdir != ddir or SYSTEM_DIR.match(e.image_loaded):
            continue
        unsigned_dll = e.image_loaded_signed is False
        signed_host = e.signed is True or bool(e.signer)
        writable = bool(USER_WRITABLE.search(e.image_loaded + "\\"))
        if not (unsigned_dll and (signed_host or writable)):
            continue
        related = [x for x in ctx.events if x.host == e.host and x.pid and x.pid == e.pid and x.evidence_id != e.evidence_id
                   and x.event_type in ("network_connection", "dns_query", "registry_set", "file_create")]
        status = "Likely" if (signed_host and writable) or related else "Suspicious"
        out.append(_f("R-DLL-001", "Chargement de DLL non signée par un binaire de confiance (DLL side-loading)",
                      "Stealth / Persistence",
                      f"{e.process_name} ({'signé' if signed_host else 'signature inconnue'}) exécuté depuis "
                      f"{pdir} a chargé la DLL non signée {e.image_loaded} située dans le même répertoire"
                      + (f" ; activité ultérieure du même processus : {len(related)} événement(s)" if related else "")
                      + ".", "High", status, 0.8 if status == "Likely" else 0.55, [e, *related[:10]], ["T1574.001"],
                      ioc_values=[e.image_loaded, e.process_path]))
    return out


def r_persistence(ctx: Ctx) -> list[Finding]:
    out = []
    run_re = re.compile(r"(?i)\\currentversion\\(run|runonce|runservices)(\\|$)|\\winlogon\\(shell|userinit)")
    for e in ctx.by_type["registry_set"]:
        if run_re.search(e.registry_key):
            val = e.registry_value
            writable = bool(USER_WRITABLE.search(val + "\\")) or bool(re.search(r"(?i)powershell|cmd /c|mshta|rundll32|wscript", val))
            out.append(_f("R-PER-001", "Persistance par clé de registre de démarrage", "Persistence",
                          f"Valeur écrite dans {e.registry_key} par {e.process_name or 'un processus inconnu'} : « {val[:200]} »."
                          + (" La cible est un emplacement accessible en écriture ou un interpréteur." if writable else ""),
                          "High" if writable else "Medium", "Likely" if writable else "Suspicious",
                          0.75 if writable else 0.5, [e], ["T1547.001"], ioc_values=[e.registry_key]))
    for e in ctx.procs:
        cmd = e.command_line or ""
        if re.search(r"(?i)\breg(\.exe)?\s+add\b.*\\currentversion\\run", cmd):
            out.append(_f("R-PER-001", "Persistance par clé de registre de démarrage (reg add)", "Persistence",
                          f"Commande : {cmd[:220]}.", "High", "Likely", 0.7, [e], ["T1547.001"]))
    for e in [*ctx.procs, *ctx.by_type["scheduled_task"]]:
        cmd = e.command_line or ""
        is_create = e.event_type == "scheduled_task" or re.search(r"(?i)schtasks(\.exe)?\s+/create|register-scheduledtask", cmd)
        if not is_create:
            continue
        benign = _mgmt_context(e)
        payload = cmd + " " + e.message + " " + e.task_name
        risky = bool(USER_WRITABLE.search(payload + "\\") or re.search(r"(?i)powershell|mshta|rundll32|wscript|cmd /c", payload))
        status = "Suspicious" if benign or not risky else "Likely"
        out.append(_f("R-PER-002", "Création de tâche planifiée", "Persistence / Execution",
                      f"Tâche planifiée créée sur {e.host or 'hôte inconnu'} : {(cmd or e.task_name or e.message)[:220]}."
                      + (" Action pointant vers un interpréteur ou un emplacement accessible en écriture." if risky else ""),
                      "Medium" if status == "Suspicious" else "High", status, 0.3 if benign else (0.7 if risky else 0.45),
                      [e], ["T1053.005"], benign_context=benign))
    groups: dict[tuple, list[NormalizedEvent]] = {}
    for e in [*ctx.procs, *ctx.by_type["service_install"]]:
        cmd = e.command_line or ""
        is_svc = e.event_type == "service_install" or re.search(r"(?i)\bsc(\.exe)?\s+create\b|new-service\s", cmd)
        if is_svc:
            image = str(e.extra.get("ImagePath", "") or e.process_path or "")
            groups.setdefault((e.host, (e.service_name or cmd)[:200].lower(), image.lower()), []).append(e)
    for (host, _name, _img), evs in groups.items():
        e = evs[0]
        image = str(e.extra.get("ImagePath", "") or e.process_path or "")
        cmd = e.command_line or ""
        text = " ".join((cmd, e.message, e.service_name, e.process_path, str(e.extra.get("ImagePath", ""))))
        psexec = bool(re.search(r"(?i)psexesvc|remcomsvc|paexec", text))
        risky = bool(USER_WRITABLE.search(text + "\\") or re.search(r"(?i)cmd(\.exe)? /c|powershell|%comspec%|mshta|rundll32", text))
        mitre = ["T1543.003"] + (["T1569.002", "T1021.002"] if psexec else [])
        benign = _mgmt_context(e)
        label = (e.service_name or cmd or e.message)[:200]
        when = f" ({len(evs)} installations)" if len(evs) > 1 else ""
        if risky and not benign:  # binaire de service dans un emplacement inscriptible ou lanceur de commandes
            sev, status, conf, note = "High", "Likely", 0.75, " Binaire ou commande du service dans un emplacement inhabituel."
        elif psexec:  # outil d'administration à double usage : suspect tant qu'il n'est pas corroboré
            sev, status, conf, note = "Medium", "Suspicious", 0.55, (" Exécution à distance de type PsExec : légitime en "
                                                                        "administration, à confirmer avec l'équipe d'exploitation.")
        else:  # installation ordinaire (pilote / programme installé) : à vérifier, pas une preuve de compromission
            sev, status, conf, note = "Low", "Inconclusive", 0.25, (" Chemin standard : installation vraisemblablement "
                                                                     "logicielle, à rapprocher du référentiel des logiciels autorisés.")
        out.append(_f("R-PER-003", "Installation de service" + (" de type PsExec (exécution à distance)" if psexec else ""),
                      "Persistence / Lateral Movement" if psexec else "Persistence",
                      f"Service installé sur {host or 'hôte inconnu'}{when} : {label}" + (f" — {image}" if image else "") + "."
                      + note, sev, status if not benign else "Suspicious", 0.3 if benign else conf, evs, mitre,
                      benign_context=benign))
    return out


def r_credential_access(ctx: Ctx) -> list[Finding]:
    out = []
    allow = {"msmpeng.exe", "csrss.exe", "wininit.exe", "lsm.exe", "mrt.exe", "sensecncproxy.exe", "werfault.exe",
             "svchost.exe", "taskmgr.exe", "vmtoolsd.exe", "csfalconservice.exe"}
    for e in ctx.by_type["process_access"]:
        if "lsass" in _lc(e.target_process) and _lc(e.process_name) not in allow:
            out.append(_f("R-CRD-001", "Accès à la mémoire de LSASS", "Credential Access",
                          f"{e.process_name or e.process_path} a ouvert lsass.exe (droits {e.granted_access or 'non précisés'}).",
                          "Critical", "Likely", 0.8, [e], ["T1003.001"]))
    for e in ctx.cmd_events():
        low = _lc(e.command_line or e.message)
        hits = []
        if re.search(r"sekurlsa|lsadump|kerberos::|privilege::debug|mimikatz", low):
            hits.append(("commandes Mimikatz", ["T1003.001"], "Critical", 0.9))
        if re.search(r"(procdump|rdrleakdiag|sqldumper)\S*\s.*lsass|comsvcs(\.dll)?[, ]+#?24|comsvcs.*minidump", low):
            hits.append(("dump de LSASS via outil système", ["T1003.001"], "Critical", 0.85))
        if re.search(r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)", low):
            hits.append(("export des ruches SAM/SYSTEM", ["T1003.002"], "High", 0.8))
        if re.search(r"ntdsutil.*(ifm|create full)|ntds\.dit", low):
            hits.append(("extraction de NTDS.dit", ["T1003.003"], "Critical", 0.85))
        for label, mitre, sev, conf in hits:
            out.append(_f("R-CRD-002", f"Vol d'identifiants : {label}", "Credential Access",
                          f"Commande observée sur {e.host or 'hôte inconnu'} : {(e.command_line or e.message)[:220]}.",
                          sev, "Likely", conf, [e], mitre))
    return out


def r_ransomware(ctx: Ctx) -> list[Finding]:
    out = []
    inhibit = []
    for e in ctx.cmd_events():
        low = _lc(e.command_line or e.message)
        if re.search(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+"
                     r"(catalog|systemstatebackup)|bcdedit(\.exe)?.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy\s+ignoreallfailures|"
                     r"get-wmiobject\s+win32_shadowcopy.*delete", low):
            inhibit.append(e)
    if inhibit:
        out.append(_f("R-RAN-001", "Destruction des mécanismes de restauration", "Impact",
                      f"{len(inhibit)} commande(s) de suppression de clichés instantanés / sauvegardes / options de "
                      f"récupération, p. ex. « {(inhibit[0].command_line or inhibit[0].message)[:160]} ».",
                      "Critical", "Likely", 0.85, inhibit, ["T1490"]))
    stops = [e for e in ctx.procs if re.search(r"(?i)(net(1)?\s+stop|sc\s+stop|taskkill\s+/f\s+/im)\s+\S*(sql|backup|veeam|vss|"
                                               r"exchange|oracle|sophos|defend)", e.command_line or "")]
    if len(stops) >= 2:
        out.append(_f("R-RAN-002", "Arrêt en série de services (sauvegarde, bases de données, sécurité)", "Impact",
                      f"{len(stops)} arrêts de services critiques observés.", "High", "Suspicious", 0.6, stops, ["T1489"]))
    writes = [e for e in ctx.events if e.event_type in ("file_create", "file_rename") and e.target_file]
    by_ext: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    notes = []
    for e in writes:
        name = e.target_file.rsplit("\\", 1)[-1].lower()
        if re.search(r"(readme|how_to|decrypt|restore|recover|ransom).*(\.txt|\.html|\.hta)$", name):
            notes.append(e)
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if ext and len(ext) <= 12 and ext not in ("tmp", "log", "txt", "dat", "lnk", "ini", "etl", "pf", "db", "json"):
            by_ext[(e.host, ext)].append(e)
    for (host, ext), evs in by_ext.items():
        if len(evs) >= 20:
            dirs = {x.target_file.rsplit("\\", 1)[0].lower() for x in evs}
            status = "Likely" if (inhibit or notes) else "Suspicious"
            out.append(_f("R-RAN-003", "Modification massive de fichiers avec une même extension", "Impact",
                          f"{len(evs)} fichiers écrits ou renommés avec l'extension « .{ext} » dans {len(dirs)} répertoire(s) sur "
                          f"{host or 'hôte inconnu'}" + (f", notes de rançon : {len(notes)}" if notes else "") + ".",
                          "Critical", status, 0.85 if status == "Likely" else 0.55, [*evs[:30], *notes[:5]], ["T1486"],
                          extension=ext, count=len(evs)))
    if notes and not any(f.rule_id == "R-RAN-003" for f in out):
        out.append(_f("R-RAN-004", "Création de notes de rançon", "Impact",
                      f"{len(notes)} fichier(s) au nom typique de note de rançon, p. ex. {notes[0].target_file}.",
                      "High", "Suspicious", 0.6, notes, ["T1486"]))
    deletes = defaultdict(list)
    for e in ctx.by_type["file_delete"]:
        deletes[(e.host, e.process_name)].append(e)
    for (host, proc), evs in deletes.items():
        if len(evs) >= 50:
            out.append(_f("R-IMP-001", "Suppression massive de fichiers", "Impact",
                          f"{proc or 'Processus inconnu'} a supprimé {len(evs)} fichiers sur {host or 'hôte inconnu'}.",
                          "High", "Suspicious", 0.6, evs[:40], ["T1485"]))
    return out


def r_auth(ctx: Ctx) -> list[Finding]:
    out = []
    fails = sorted(ctx.by_type["logon_failure"], key=lambda e: e.timestamp or e.record_index)
    succ = ctx.by_type["logon_success"]
    by_src: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in fails:
        by_src[e.src_ip or e.host or "inconnue"].append(e)
    for src, evs in by_src.items():
        users = Counter(_lc(e.user or e.target_user) for e in evs)
        if len(evs) < 10:
            continue
        span = ""
        if evs[0].timestamp and evs[-1].timestamp:
            span = f" en {int((evs[-1].timestamp - evs[0].timestamp).total_seconds() // 60) + 1} min"
        spraying = len(users) >= 5
        mitre = ["T1110.003"] if spraying else ["T1110.001"]
        kind = "Password spraying" if spraying else "Brute force"
        followed = []
        if evs[-1].timestamp:
            for s in succ:
                if (s.src_ip == src or (not s.src_ip and s.host == src)) and _lc(s.user or s.target_user) in users and \
                        s.timestamp and timedelta(0) <= s.timestamp - evs[-1].timestamp <= timedelta(hours=2):
                    followed.append(s)
        desc = (f"{kind} : {len(evs)} échecs d'authentification depuis {src}{span}, visant {len(users)} compte(s) "
                f"({', '.join(list(users)[:6])}).")
        sev = "Medium"
        status, conf = "Likely", 0.8
        if followed:
            desc += f" Une authentification RÉUSSIE suit pour {followed[0].user or followed[0].target_user} : compromission de compte probable."
            mitre.append("T1078")
            sev, conf = "High", 0.8
        scope = classify_ip(src)
        if scope and scope[1] == "publique":
            desc += " Source : adresse IP publique."
        out.append(_f("R-AUTH-001", kind + (" suivi d'une connexion réussie" if followed else ""), "Credential Access",
                      desc, sev, status, conf, [*evs[:40], *followed], mitre, attempts=len(evs), accounts=len(users),
                      ioc_values=[src]))
    return out


def r_lateral(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.cmd_events():
        cmd = e.command_line or e.message
        if re.search(r"(?i)\bpsexec(64)?(\.exe)?\b.*\\\\", cmd):
            out.append(_f("R-LAT-001", "Exécution à distance via PsExec", "Lateral Movement",
                          f"Commande : {cmd[:220]}.", "High", "Likely", 0.75, [e], ["T1021.002", "T1569.002"]))
        elif re.search(r"(?i)wmic(\.exe)?\s+/node:\S+\s+process\s+call\s+create", cmd):
            out.append(_f("R-LAT-002", "Exécution à distance via WMI", "Lateral Movement / Execution",
                          f"Commande : {cmd[:220]}.", "High", "Likely", 0.75, [e], ["T1047"]))
        elif re.search(r"(?i)(invoke-command|enter-pssession|new-pssession)\b.*-computername", cmd):
            out.append(_f("R-LAT-003", "Commande PowerShell à distance (WinRM)", "Lateral Movement",
                          f"Commande : {cmd[:220]}.", "Medium", "Suspicious", 0.55, [e], ["T1021.006"]))
    for e in ctx.procs:
        if _lc(e.parent_name) == "wmiprvse.exe" and _lc(e.process_name) in ("powershell.exe", "cmd.exe"):
            out.append(_f("R-LAT-004", "Interpréteur lancé par WmiPrvSE (exécution WMI)", "Execution",
                          f"{e.process_name} lancé par WmiPrvSE.exe : {(e.command_line or '')[:180]}.", "Medium",
                          "Suspicious", 0.55, [e], ["T1047"]))
        if _lc(e.parent_name) == "wsmprovhost.exe":
            out.append(_f("R-LAT-005", "Commande exécutée via PowerShell Remoting", "Lateral Movement",
                          f"{e.process_name} lancé par wsmprovhost.exe.", "Medium", "Suspicious", 0.55, [e], ["T1021.006"]))
    rdp = [e for e in ctx.by_type["logon_success"] if e.logon_type.strip() in ("10", "RemoteInteractive")]
    if rdp:
        sources = {e.src_ip for e in rdp if e.src_ip}
        out.append(_f("R-LAT-006", "Ouvertures de session RDP", "Lateral Movement",
                      f"{len(rdp)} ouverture(s) de session RDP (type 10) depuis {', '.join(sorted(sources)) or 'source inconnue'}. "
                      "Activité légitime possible : à corréler avec le reste de la chaîne.", "Low", "Suspicious", 0.35,
                      rdp, ["T1021.001"]))
    return out


DISCOVERY = [
    (r"\bwhoami\b", "T1033"), (r"\bnet1?(\.exe)?\s+(group|user)\b.*\/domain", "T1087.002"),
    (r"\bnet1?(\.exe)?\s+group\s+\"?domain admins", "T1069.002"), (r"\bnltest\b.*(dclist|domain_trusts)", "T1018"),
    (r"\bipconfig\b\s*/all", "T1016"), (r"\bsysteminfo\b", "T1082"), (r"\bnet1?(\.exe)?\s+view\b", "T1018"),
    (r"\barp\s+-a\b", "T1016"), (r"\bquser\b|\bquery\s+user\b", "T1033"), (r"adfind|get-aduser|get-adcomputer", "T1087.002"),
    (r"\bnet1?(\.exe)?\s+accounts\b", "T1201"),
]


def r_discovery(ctx: Ctx) -> list[Finding]:
    by_host: dict[str, list[tuple[NormalizedEvent, str]]] = defaultdict(list)
    for e in ctx.procs:
        for pat, tid in DISCOVERY:
            if re.search(pat, e.command_line or "", re.I):
                by_host[e.host].append((e, tid))
                break
    out = []
    for host, items in by_host.items():
        distinct = {re.sub(r"\s+", " ", _lc(e.command_line))[:60] for e, _ in items}
        if len(distinct) >= 3:
            evs = [e for e, _ in items]
            out.append(_f("R-DIS-001", "Reconnaissance interne (série de commandes de découverte)", "Discovery",
                          f"{len(distinct)} commandes de découverte distinctes sur {host or 'hôte inconnu'} : "
                          + "; ".join(sorted(distinct)[:6]) + ".", "Medium", "Suspicious", 0.6, evs,
                          sorted({t for _, t in items})))
    return out


def r_network(ctx: Ctx) -> list[Finding]:
    out = []
    conns = [e for e in ctx.by_type["network_connection"] if e.dst_ip]
    script_conns = []
    for e in conns:
        scope = classify_ip(e.dst_ip)
        if scope and scope[1] in ("publique", "documentation (RFC 5737)") and _lc(e.process_name) in SCRIPT_HOSTS:
            script_conns.append(e)
    if script_conns:
        e = script_conns[0]
        out.append(_f("R-NET-001", "Connexion externe initiée par un interpréteur ou un binaire système détourné",
                      "Command and Control", f"{len(script_conns)} connexion(s) sortante(s) de {e.process_name} vers "
                      + ", ".join(sorted({f'{x.dst_ip}:{x.dst_port}' for x in script_conns})[:5]) + ".",
                      "High", "Likely", 0.7, script_conns, ["T1071.001"] if any(x.dst_port in (80, 443) for x in script_conns)
                      else ["T1571"], ioc_values=[x.dst_ip for x in script_conns]))
    flows: dict[tuple[str, str, str, int | None], list[NormalizedEvent]] = defaultdict(list)
    for e in conns:
        if e.timestamp:
            flows[(e.host, _lc(e.process_name), e.dst_ip, e.dst_port)].append(e)
    for (host, proc, dst, port), evs in flows.items():
        scope = classify_ip(dst)
        if len(evs) < 6 or not scope or scope[1] not in ("publique", "documentation (RFC 5737)"):
            continue
        evs.sort(key=lambda x: x.timestamp)
        gaps = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(evs, evs[1:])]
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv < 0.25 and mean >= 5:
            mitre = ["T1071.001"] if port in (80, 443, 8080, 8443) else ["T1571"]
            out.append(_f("R-NET-002", "Communications périodiques (beaconing)", "Command and Control",
                          f"{proc or 'Processus inconnu'} sur {host or 'hôte inconnu'} contacte {dst}:{port} {len(evs)} fois "
                          f"à intervalle régulier (~{mean:.0f} s, coefficient de variation {cv:.2f}).",
                          "High", "Likely" if proc not in ("svchost.exe", "msedge.exe", "chrome.exe") else "Suspicious",
                          0.7, evs, mitre, interval_seconds=round(mean, 1), ioc_values=[dst]))
    for e in conns:
        if e.dst_port in (4444, 1337, 31337, 6667, 9001, 5555) and classify_ip(e.dst_ip) and \
                classify_ip(e.dst_ip)[1] in ("publique", "documentation (RFC 5737)"):  # type: ignore[index]
            out.append(_f("R-NET-003", "Connexion vers un port atypique souvent associé aux outils offensifs",
                          "Command and Control", f"{e.process_name or 'Processus inconnu'} → {e.dst_ip}:{e.dst_port}.",
                          "Medium", "Suspicious", 0.5, [e], ["T1571"], ioc_values=[e.dst_ip]))
    return out


def r_dns(ctx: Ctx) -> list[Finding]:
    out = []
    dns = [e for e in ctx.by_type["dns_query"] if e.dns_query]
    by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in dns:
        by_host[e.host].append(e)
    for host, evs in by_host.items():
        weird = [e for e in evs if len(e.dns_query.split(".")[0]) >= 12 and entropy(e.dns_query.split(".")[0]) > 3.4]
        nx = [e for e in evs if re.search(r"(?i)nxdomain|9003|^3$|non-existent", e.dns_rcode or "")]
        if len(weird) >= 5 or len(nx) >= 10:
            sample = sorted({e.dns_query for e in (weird or nx)})[:5]
            out.append(_f("R-DNS-001", "Résolutions DNS de domaines pseudo-aléatoires (DGA possible)", "Command and Control",
                          f"{len(weird)} requête(s) à forte entropie et {len(nx)} réponse(s) NXDOMAIN depuis {host or 'hôte inconnu'} ; "
                          f"exemples : {', '.join(sample)}.", "High", "Suspicious", 0.6, (weird or nx)[:30], ["T1568.002"],
                          ioc_values=sample))
        parents: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in evs:
            labels = e.dns_query.split(".")
            if len(labels) >= 3 and len(labels[0]) >= 30:
                parents[".".join(labels[-2:])].append(e)
        for parent, items in parents.items():
            if len(items) >= 10:
                out.append(_f("R-DNS-002", "Sous-domaines longs et nombreux (tunneling DNS possible)", "Command and Control",
                              f"{len(items)} requêtes vers des sous-domaines longs de {parent} depuis {host or 'hôte inconnu'}.",
                              "High", "Suspicious", 0.6, items[:30], ["T1071.004"], ioc_values=[parent]))
    return out


def r_usb(ctx: Ctx) -> list[Finding]:
    out = []
    usb_hosts = {e.host for e in ctx.by_type["usb_device"]}
    for e in ctx.procs:
        path = e.process_path or ""
        m = re.match(r"(?i)^([d-z]):\\", path)
        if not m:
            continue
        removable_hint = e.host in usb_hosts or re.search(r"(?i)removable|usb", str(e.extra))
        if removable_hint:
            usb_evs = [u for u in ctx.by_type["usb_device"] if u.host == e.host]
            out.append(_f("R-USB-001", "Exécution d'un programme depuis un support amovible", "Initial Access / Lateral Movement",
                          f"{path} exécuté sur {e.host or 'hôte inconnu'} après la connexion d'un périphérique USB.",
                          "High", "Likely", 0.7, [e, *usb_evs[:3]], ["T1091"], ioc_values=[path]))
        else:
            out.append(_f("R-USB-002", "Exécution depuis un lecteur non système", "Execution",
                          f"{path} exécuté depuis le lecteur {m.group(1).upper()}: ; la nature amovible n'est pas "
                          "confirmée par les données disponibles.", "Low", "Suspicious", 0.3, [e], []))
    return out


def r_defense(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.cmd_events():
        cmd = e.command_line or e.message
        if re.search(r"(?i)set-mppreference\s.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection)\s+(\$true|1)|"
                     r"add-mppreference\s.*-exclusion(path|process|extension)|sc(\.exe)?\s+(stop|config)\s+windefend|"
                     r"disableantispyware", cmd):
            benign = _mgmt_context(e)
            out.append(_f("R-DEF-001", "Désactivation ou affaiblissement de l'antivirus", "Defense Impairment",
                          f"Commande : {cmd[:220]}.", "High", "Suspicious" if benign else "Likely",
                          0.4 if benign else 0.8, [e], ["T1685"], benign_context=benign))
        if re.search(r"(?i)wevtutil(\.exe)?\s+cl\b|clear-eventlog|remove-eventlog", cmd):
            out.append(_f("R-DEF-002", "Effacement des journaux d'événements", "Defense Impairment",
                          f"Commande : {cmd[:200]}.", "High", "Likely", 0.8, [e], ["T1685.005"]))
    cleared = ctx.by_type["log_cleared"]
    if cleared:
        out.append(_f("R-DEF-003", "Journal d'audit effacé (Event ID 1102/104)", "Defense Impairment",
                      f"{len(cleared)} événement(s) d'effacement de journal.", "High", "Likely", 0.8, cleared, ["T1685.005"]))
    return out


def r_accounts(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.procs:
        cmd = e.command_line or ""
        if re.search(r"(?i)\bnet1?(\.exe)?\s+user\s+\S+\s+\S*\s*/add", cmd):
            out.append(_f("R-ACC-001", "Création de compte local en ligne de commande", "Persistence",
                          f"Commande : {cmd[:200]}.", "Medium", "Suspicious", 0.6, [e], ["T1136.001"]))
        if re.search(r"(?i)\bnet1?(\.exe)?\s+(localgroup|group)\s+\"?(administrat|domain admins)\S*\"?\s+\S+\s*/add", cmd):
            out.append(_f("R-ACC-002", "Ajout d'un compte à un groupe d'administration", "Persistence / Privilege Escalation",
                          f"Commande : {cmd[:200]}.", "High", "Likely", 0.75, [e], ["T1098"]))
    for e in ctx.by_type["account_change"]:
        if e.event_code == "4720":
            out.append(_f("R-ACC-003", "Compte utilisateur créé (4720)", "Persistence",
                          f"Compte {e.target_user or '?'} créé par {e.user or '?'}.", "Medium", "Suspicious", 0.45, [e], ["T1136.001"]))
    for e in ctx.by_type["group_change"]:
        if re.search(r"(?i)admin", e.group_name or e.message):
            out.append(_f("R-ACC-004", "Ajout à un groupe à privilèges", "Persistence / Privilege Escalation",
                          f"{e.target_user or 'Un compte'} ajouté à {e.group_name or 'un groupe d’administration'} par {e.user or '?'}.",
                          "High", "Suspicious", 0.55, [e], ["T1098"]))
    for e in ctx.by_type["registry_set"]:
        if re.search(r"(?i)\\(ms-settings|mscfile|exefile)\\shell\\open\\command", e.registry_key):
            out.append(_f("R-PRV-001", "Contournement de l'UAC (détournement de clé shell\\open\\command)",
                          "Privilege Escalation", f"Clé {e.registry_key} = « {e.registry_value[:150]} ».", "High",
                          "Likely", 0.75, [e], ["T1548.002"]))
    return out


def r_injection(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.by_type["process_access"]:
        if "lsass" in _lc(e.target_process):
            continue
        acc = e.granted_access.lower()
        remote_thread = e.event_code == "8" or "createremotethread" in _lc(e.action + e.event_code)
        if remote_thread or (acc in ("0x1fffff", "0x1f0fff", "0x143a") and USER_WRITABLE.search((e.process_path or "") + "\\")):
            out.append(_f("R-INJ-001", "Injection de code dans un autre processus", "Stealth / Privilege Escalation",
                          f"{e.process_name or e.process_path} → {e.target_process} "
                          f"({'CreateRemoteThread' if remote_thread else 'accès ' + acc}).", "High", "Likely", 0.7, [e], ["T1055"]))
    return out


def r_kms(ctx: Ctx) -> list[Finding]:
    hits = []
    for e in ctx.events:
        blob = _lc(" ".join((e.process_name, e.process_path, e.command_line, e.parent_name, e.target_file,
                             e.service_name, e.task_name, e.registry_key, e.registry_value, e.message, e.alert_name)))
        tokens = [t for t in KMS_TOKENS if t in blob]
        if tokens:
            hits.append((e, tokens))
    if not hits:
        return []
    tokens = sorted({t for _, ts in hits for t in ts})
    evs = [e for e, _ in hits]
    kinds = {e.event_type for e in evs}
    status = "Confirmed" if len(hits) >= 2 and len(kinds) >= 2 else "Likely"
    return [_f("R-PUA-001", "Activateur KMS non autorisé (KMSPico ou équivalent)", "Unauthorized Software / PUA",
               f"{len(hits)} événement(s) référencent un activateur de licences illégitime ({', '.join(tokens)}). "
               "Ces outils sont des logiciels indésirables qui désactivent souvent l'antivirus et sont fréquemment "
               "distribués avec des malwares. Les comportements associés (exclusions antivirus, tâches, services) "
               "font l'objet de findings distinctes le cas échéant.", "Medium", status,
               0.9 if status == "Confirmed" else 0.7, evs[:30], [], tokens=tokens)]


def r_alerts(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.by_type["alert"]:
        verdict = _lc(e.alert_verdict + " " + e.message)
        sev_raw = _lc(e.alert_severity)
        sev = "Critical" if "crit" in sev_raw or sev_raw in ("5", "10", "9") else \
            "High" if "high" in sev_raw or sev_raw in ("4", "8", "7") else \
            "Medium" if "med" in sev_raw or sev_raw in ("3", "5", "6") else "Low" if sev_raw else "Medium"
        if e.source_product.startswith("Saisie manuelle"):
            out.append(_f("R-ALR-000", f"Signalement analyste : {e.alert_name or 'saisie manuelle'}", "Analyst Input",
                          "Informations saisies manuellement par l'analyste (non corroborées par des journaux).",
                          sev, "Inconclusive", 0.2, [e], []))
            continue
        confirmed = re.search(r"true[ _-]?positive|malicious|malware|quarantin|blocked|prevented|remediated|killed|"
                              r"compromised|ransomware", verdict)
        benign = re.search(r"false[ _-]?positive|benign|informational expected|allowed by policy", verdict)
        if benign:
            status, conf = "False Positive", 0.7
        elif confirmed:
            status, conf = "Confirmed", 0.85
        else:
            status, conf = "Suspicious", 0.5
        out.append(_f("R-ALR-001", f"Alerte {e.source_product or 'sécurité'} : {e.alert_name or 'sans titre'}",
                      "Security Product Alert",
                      f"Alerte émise par {e.source_product or 'un produit de sécurité'} (sévérité éditeur : {e.alert_severity or 'n/c'}"
                      f", statut : {e.alert_verdict or 'n/c'}) sur {e.host or 'hôte non précisé'}. "
                      + ("Le produit indique une détection/blocage effectif." if confirmed else
                         "Le produit qualifie l'alerte de bénigne." if benign else "Qualification à confirmer par l'analyse."),
                      sev, status, conf, [e], [t for t in e.mitre_hint], vendor_mitre=e.mitre_hint))
    return out


def r_email(ctx: Ctx) -> list[Finding]:
    out = []
    risky_ext = re.compile(r"(?i)\.(exe|scr|js|jse|vbs|vbe|hta|iso|img|lnk|docm|xlsm|pptm|one|html?|wsf|bat|cmd|ps1|zip|rar|7z)$")
    for e in ctx.by_type["email"]:
        if e.event_code.lower() in ("emailattachment", "emailurl") or e.action.lower() in ("emailattachment", "emailurl"):
            continue
        signals = []
        if re.search(r"(?i)(spf|dkim|dmarc)=(fail|softfail|none|permerror)", e.email_auth):
            signals.append(f"authentification de l'expéditeur en échec ({e.email_auth})")
        dom = lambda a: a.split("@")[-1].strip(">").lower() if "@" in a else ""  # noqa: E731
        if e.email_reply_to and dom(e.email_reply_to) and dom(e.email_reply_to) != dom(e.email_from):
            signals.append(f"adresse de réponse différente de l'expéditeur ({e.email_reply_to})")
        risky = [a for a in e.attachments if risky_ext.search(a)]
        if risky:
            signals.append("pièce(s) jointe(s) à extension à risque : " + ", ".join(risky[:5]))
        urls = e.extra.get("Urls") or ""
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", str(urls) + " " + e.message):
            signals.append("lien vers une adresse IP brute")
        if re.search(r"(?i)urgent|facture impayée|password expire|verify your account|mot de passe expir|virement", e.email_subject):
            signals.append("objet à caractère d'urgence ou d'ingénierie sociale")
        if not signals:
            continue
        mitre = (["T1566.001"] if risky else []) + (["T1566.002"] if "lien" in " ".join(signals) else [])
        status = "Likely" if len(signals) >= 2 else "Suspicious"
        out.append(_f("R-MAIL-001", "E-mail présentant des caractéristiques d'hameçonnage", "Initial Access",
                      f"Message de {e.email_from or '?'} à {e.email_to or '?'} (« {e.email_subject[:120]} ») : "
                      + " ; ".join(signals) + ".", "High" if status == "Likely" else "Medium", status,
                      0.7 if status == "Likely" else 0.45, [e], mitre or ["T1566"], ioc_values=[e.email_from]))
    return out


def r_static(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.events:
        sa = e.extra.get("static_analysis") if isinstance(e.extra, dict) else None
        if not sa:
            continue
        ind = sa.get("indicators", [])
        strong = [i for i in ind if "injection" in i or "hollowing" in i or "dump" in i]
        packed = any("entropie" in i for i in ind)
        if sa.get("yara_matches") or strong or (packed and len(ind) >= 2):
            out.append(_f("R-STA-001", "Exécutable aux caractéristiques suspectes (analyse statique)", "Malware Analysis",
                          f"{e.target_file} : " + "; ".join(ind[:6]) + (f" ; règles YARA : {', '.join(sa['yara_matches'])}"
                                                                         if sa.get("yara_matches") else "") + ".",
                          "Medium", "Suspicious", 0.5, [e], ["T1027.002"] if packed else []))
    return out


def r_linux(ctx: Ctx) -> list[Finding]:
    out = []
    for e in ctx.cmd_events():
        cmd = e.command_line or e.message
        if re.search(r"bash\s+-i\s+>&\s*/dev/tcp/|nc(at)?\s+(-e|-c)\s+/bin/(ba)?sh|python[23]?\s+-c\s+['\"]import\s+socket|"
                     r"socat\s+exec:", cmd, re.I):
            out.append(_f("R-LNX-001", "Shell inversé (reverse shell)", "Execution / Command and Control",
                          f"Commande : {cmd[:200]}.", "Critical", "Likely", 0.85, [e], ["T1059.004"]))
        if re.search(r"(curl|wget)\s+[^|]+\|\s*(ba)?sh", cmd, re.I):
            out.append(_f("R-LNX-002", "Téléchargement puis exécution directe d'un script", "Execution",
                          f"Commande : {cmd[:200]}.", "High", "Likely", 0.7, [e], ["T1059.004", "T1105"]))
        if re.search(r"crontab\s+-|/etc/cron\.d/|>>\s*/etc/crontab", cmd, re.I):
            out.append(_f("R-LNX-003", "Modification de cron (persistance possible)", "Persistence",
                          f"Commande : {cmd[:200]}.", "Medium", "Suspicious", 0.5, [e], ["T1053.003"]))
    return out


RULES: list[Callable[[Ctx], list[Finding]]] = [
    r_alerts, r_email, r_office_child, r_powershell, r_lolbins, r_user_writable_exec, r_dll_sideloading,
    r_persistence, r_credential_access, r_ransomware, r_auth, r_lateral, r_discovery, r_network, r_dns, r_usb,
    r_defense, r_accounts, r_injection, r_kms, r_static, r_linux,
]


def run_rules(events: list[NormalizedEvent]) -> tuple[list[Finding], list[str]]:
    ctx = Ctx(events)
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:  # noqa: BLE001 - une règle défaillante ne bloque pas l'investigation
            errors.append(f"{rule.__name__} : {type(exc).__name__} {exc}")
    return findings, errors
