"""Bibliothèque d'hypothèses de Threat Hunting (KQL Defender XDR / Sentinel, Splunk SPL, Sigma).

Schémas ciblés :
- KQL : tables Advanced Hunting de Microsoft Defender XDR (DeviceProcessEvents, DeviceNetworkEvents,
  DeviceRegistryEvents, DeviceImageLoadEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents) ;
  certaines requêtes utilisent SecurityEvent (Microsoft Sentinel, agent AMA/Windows Security Events).
- SPL : Sysmon via l'add-on Splunk (sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational) et
  journal Security Windows ; le nom d'index (`index=wineventlog`/`index=sysmon`) est À ADAPTER.
- Sigma : format Sigma 2 (logsource category/product), convertible avec pySigma.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

ADAPT = ("Champs/index à adapter : noms d'index Splunk, rétention de la table, exclusions propres à "
         "l'environnement (outils d'administration, chemins de déploiement).")


@dataclass
class Hypothesis:
    hid: str
    name: str
    objective: str
    hypothesis: str
    behaviors: list[str]
    data_sources: list[str]
    kql: str
    spl: str
    sigma: str
    expected_results: str
    validation: str
    recommendations: list[str]
    mitre: list[str]
    rules: list[str] = field(default_factory=list)
    adapt_note: str = ADAPT

    def to_dict(self) -> dict:
        return asdict(self)


def _sigma(title: str, uid: str, desc: str, category: str, detection: str, fps: list[str], level: str, tags: list[str],
           product: str = "windows") -> str:
    fp = "\n".join(f"    - {f}" for f in fps)
    tg = "\n".join(f"    - {t}" for t in tags)
    return (f"title: {title}\nid: {uid}\nstatus: experimental\ndescription: {desc}\nauthor: AI SOC ANALYST\n"
            f"date: 2026-11-26\ntags:\n{tg}\nlogsource:\n    category: {category}\n    product: {product}\n"
            f"detection:\n{detection}\nfalsepositives:\n{fp}\nlevel: {level}\n")


def _sigma_corr(title: str, base_id: str, corr_id: str, name: str, desc: str, base_detection: str, group_by: str,
                timespan: str, gte: int, level: str, tags: list[str], fps: list[str]) -> str:
    """Règle Sigma de base + règle de corrélation (spécification Sigma 2 « correlation rules »)."""
    tg = "\n".join(f"    - {t}" for t in tags)
    fp = "\n".join(f"    - {f}" for f in fps)
    return (f"title: {title} (événement de base)\nid: {base_id}\nname: {name}\nstatus: experimental\n"
            f"description: {desc}\nauthor: AI SOC ANALYST\ndate: 2026-11-26\ntags:\n{tg}\n"
            f"logsource:\n    product: windows\n    service: security\ndetection:\n{base_detection}\n"
            f"falsepositives:\n{fp}\nlevel: low\n---\n"
            f"title: {title}\nid: {corr_id}\nstatus: experimental\ndescription: {desc}\nauthor: AI SOC ANALYST\n"
            f"date: 2026-11-26\ncorrelation:\n    type: event_count\n    rules:\n        - {name}\n"
            f"    group-by:\n        - {group_by}\n    timespan: {timespan}\n    condition:\n        gte: {gte}\n"
            f"falsepositives:\n{fp}\nlevel: {level}\n")


HYPOTHESES: list[Hypothesis] = [
    Hypothesis(
        "H-01", "Suspicious PowerShell Execution",
        "Identifier les exécutions PowerShell encodées, cachées ou téléchargeant du code.",
        "Un attaquant utilise PowerShell avec -EncodedCommand ou un téléchargement en mémoire pour exécuter une charge.",
        ["Paramètres -enc/-EncodedCommand", "-w hidden / -nop / -ExecutionPolicy Bypass",
         "IEX, DownloadString, Net.WebClient, Invoke-WebRequest", "Parent inhabituel (Office, navigateur, wmiprvse)"],
        ["DeviceProcessEvents (Defender XDR)", "Sysmon EID 1", "PowerShell Script Block Logging (4104)"],
        """DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\\s-(e|en|enc|encodedcommand)\\s"
    or ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Net.WebClient", "Invoke-WebRequest", "IEX")
    or ProcessCommandLine matches regex @"(?i)-w(indowstyle)?\\s+h(idden)?"
| summarize Executions = count(), Hosts = dcount(DeviceName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by InitiatingProcessFileName, ProcessCommandLine
| order by Hosts asc, Executions desc""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (Image="*\\\\powershell.exe" OR Image="*\\\\pwsh.exe")
    (CommandLine="* -enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*DownloadString*"
     OR CommandLine="*Net.WebClient*" OR CommandLine="*-w hidden*" OR CommandLine="*IEX*")
| stats count dc(host) as hosts min(_time) as first_seen max(_time) as last_seen by ParentImage CommandLine
| sort hosts""",
        _sigma("Suspicious PowerShell Execution", "4f2c1a3e-1b6f-4c55-9a01-0d6b8a7c1e01",
               "PowerShell encodé, caché ou téléchargeant du code", "process_creation",
               "    selection_img:\n        Image|endswith:\n            - '\\powershell.exe'\n            - '\\pwsh.exe'\n"
               "    selection_cli:\n        CommandLine|contains:\n            - ' -enc '\n            - ' -EncodedCommand '\n"
               "            - 'DownloadString'\n            - 'Net.WebClient'\n            - ' -w hidden '\n"
               "    condition: selection_img and selection_cli",
               ["Scripts d'administration et de déploiement (SCCM, Intune)"], "high",
               ["attack.execution", "attack.t1059.001", "attack.t1027.010"]),
        "Lignes de commande rares (présentes sur peu d'hôtes) avec contenu encodé ou téléchargement.",
        "Décoder le Base64 (UTF-16LE), identifier l'URL/charge, vérifier le parent et l'utilisateur, rechercher les "
        "connexions réseau du processus.",
        ["Activer le Script Block Logging et l'AMSI", "Restreindre PowerShell (Constrained Language Mode, WDAC)",
         "Créer une détection sur les combinaisons parent Office + PowerShell"],
        ["T1059.001", "T1027.010", "T1105"], ["R-PS-001"]),
    Hypothesis(
        "H-02", "DLL Sideloading",
        "Détecter le chargement de DLL non signées par des binaires de confiance hors répertoires système.",
        "Un attaquant dépose un exécutable signé et une DLL malveillante dans un répertoire inscriptible.",
        ["DLL non signée chargée depuis le répertoire du binaire", "Binaire signé exécuté depuis AppData/ProgramData/Public",
         "Activité réseau ou persistance du même processus"],
        ["DeviceImageLoadEvents", "Sysmon EID 7 (Image Loaded)", "DeviceProcessEvents"],
        """DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"(?i)\\\\(users\\\\public|programdata|appdata|temp)\\\\"
| extend DllDir = tostring(split(FolderPath, FileName)[0]),
         ProcDir = tostring(split(InitiatingProcessFolderPath, InitiatingProcessFileName)[0])
| where DllDir =~ ProcDir
| join kind=leftanti (DeviceFileCertificateInfo | where IsSigned == true | distinct SHA1) on SHA1
| summarize Hosts = dcount(DeviceName), Loads = count() by InitiatingProcessFileName, FolderPath, SHA256
| order by Hosts asc""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 Signed="false"
    (ImageLoaded="*\\\\Users\\\\Public\\\\*" OR ImageLoaded="*\\\\ProgramData\\\\*" OR ImageLoaded="*\\\\AppData\\\\*")
| rex field=Image "(?<proc_dir>.*)\\\\\\\\[^\\\\\\\\]+$"
| rex field=ImageLoaded "(?<dll_dir>.*)\\\\\\\\[^\\\\\\\\]+$"
| where proc_dir == dll_dir
| stats count dc(host) as hosts by Image ImageLoaded
| sort hosts""",
        _sigma("Unsigned DLL Loaded From Binary Directory In User-Writable Path", "9a1e4b52-3d0f-4b77-8b2e-6c3a2f9e7d02",
               "DLL non signée chargée par un processus depuis un répertoire inscriptible", "image_load",
               "    selection:\n        ImageLoaded|contains:\n            - '\\Users\\Public\\'\n            - '\\ProgramData\\'\n"
               "            - '\\AppData\\'\n        Signed: 'false'\n    condition: selection",
               ["Applications installées par utilisateur (Teams, Zoom) avec DLL non signées"], "medium",
               ["attack.persistence", "attack.t1574.001"]),
        "Couples binaire signé / DLL non signée rares, hors chemins d'installation standards.",
        "Vérifier l'éditeur du binaire, l'origine de la DLL (hash, date de création), et l'activité du processus.",
        ["Bloquer l'exécution depuis les répertoires inscriptibles (WDAC/AppLocker)", "Surveiller Sysmon EID 7 sur les postes"],
        ["T1574.001"], ["R-DLL-001"]),
    Hypothesis(
        "H-03", "Ransomware Behavior",
        "Détecter les actions préparatoires et le chiffrement massif caractéristiques d'un ransomware.",
        "Un acteur supprime les sauvegardes puis chiffre des fichiers en masse.",
        ["vssadmin delete shadows / wbadmin delete catalog / bcdedit recoveryenabled no", "Arrêt de services de sauvegarde",
         "Renommage massif avec une même extension", "Création de notes de rançon"],
        ["DeviceProcessEvents", "DeviceFileEvents", "Sysmon EID 1/11"],
        """let inhibit = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete catalog", "recoveryenabled no")
| project Timestamp, DeviceName, InhibitCmd = ProcessCommandLine;
let mass = DeviceFileEvents
| where Timestamp > ago(1d) and ActionType in ("FileRenamed", "FileModified", "FileCreated")
| extend Ext = tostring(split(FileName, ".")[-1])
| summarize Files = count() by DeviceName, Ext, bin(Timestamp, 5m)
| where Files > 100;
inhibit | join kind=fullouter mass on DeviceName
| project DeviceName, InhibitCmd, Ext, Files""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*delete catalog*"
     OR CommandLine="*recoveryenabled no*")
| table _time host User Image CommandLine ParentImage""",
        _sigma("Shadow Copy Or Backup Catalog Deletion", "0c7d5e61-8a22-4f3b-a5e3-8d4b1f6a9c03",
               "Suppression des clichés instantanés ou du catalogue de sauvegarde", "process_creation",
               "    selection:\n        CommandLine|contains:\n            - 'delete shadows'\n            - 'shadowcopy delete'\n"
               "            - 'delete catalog'\n            - 'recoveryenabled no'\n    condition: selection",
               ["Opérations de maintenance documentées des sauvegardes"], "critical", ["attack.impact", "attack.t1490"]),
        "Commandes de destruction des sauvegardes et pics de modifications de fichiers sur un même hôte.",
        "Confirmer la chronologie, identifier le compte et le vecteur de propagation, isoler immédiatement les hôtes.",
        ["Protéger les sauvegardes (immuables / hors ligne)", "Activer la protection anti-ransomware de l'EDR"],
        ["T1490", "T1486"], ["R-RAN-001", "R-RAN-003"]),
    Hypothesis(
        "H-04", "Credential Dumping",
        "Repérer les accès à LSASS et l'extraction des bases d'identifiants.",
        "Un attaquant ayant des droits élevés extrait les secrets de LSASS, SAM ou NTDS.",
        ["Accès à lsass.exe par des processus inhabituels", "comsvcs.dll MiniDump, procdump -ma lsass",
         "reg save HKLM\\SAM/SYSTEM", "ntdsutil ifm"],
        ["DeviceProcessEvents", "DeviceEvents (OpenProcessApiCall)", "Sysmon EID 10"],
        """DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("procdump", "comsvcs", "MiniDump", "rdrleakdiag"))
    or ProcessCommandLine has_any ("sekurlsa", "lsadump")
    or (ProcessCommandLine has "reg" and ProcessCommandLine has "save" and ProcessCommandLine has_any ("hklm\\\\sam", "hklm\\\\system", "hklm\\\\security"))
    or (FileName =~ "ntdsutil.exe" and ProcessCommandLine has "ifm")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\\\lsass.exe"
    NOT (SourceImage="*\\\\MsMpEng.exe" OR SourceImage="*\\\\csrss.exe" OR SourceImage="*\\\\wininit.exe")
| stats count by host SourceImage GrantedAccess""",
        _sigma("LSASS Memory Dump Via Comsvcs Or Procdump", "5e8f2d10-7c44-4a1b-9e6d-3f2a1b0c9d04",
               "Dump mémoire de LSASS via comsvcs.dll ou procdump", "process_creation",
               "    selection_comsvcs:\n        CommandLine|contains|all:\n            - 'comsvcs'\n            - 'MiniDump'\n"
               "    selection_procdump:\n        CommandLine|contains|all:\n            - 'procdump'\n            - 'lsass'\n"
               "    condition: 1 of selection_*",
               ["Diagnostics autorisés par le support Microsoft"], "critical", ["attack.credential-access", "attack.t1003.001"]),
        "Peu ou pas de résultats attendus ; tout résultat est à investiguer en priorité.",
        "Identifier l'utilisateur et le parent, vérifier la création du fichier de dump, réinitialiser les identifiants exposés.",
        ["Activer LSA Protection (RunAsPPL) et Credential Guard", "Règles ASR de protection de LSASS"],
        ["T1003.001", "T1003.002", "T1003.003"], ["R-CRD-001", "R-CRD-002"]),
    Hypothesis(
        "H-05", "Suspicious Scheduled Tasks",
        "Identifier les tâches planifiées créées pour la persistance ou l'exécution.",
        "Un attaquant crée une tâche planifiée exécutant un interpréteur ou un binaire d'un répertoire inscriptible.",
        ["schtasks /create avec powershell/cmd/mshta", "Action pointant vers AppData/Temp/ProgramData", "Event 4698"],
        ["DeviceProcessEvents", "SecurityEvent 4698 (Sentinel)", "Sysmon EID 1"],
        """DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell", "cmd /c", "mshta", "rundll32", "wscript", "\\\\AppData\\\\", "\\\\Temp\\\\", "\\\\ProgramData\\\\")
| where InitiatingProcessFileName !in~ ("CcmExec.exe", "IntuneManagementExtension.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName""",
        """index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4698
| rex field=TaskContent "<Command>(?<task_command>[^<]+)</Command>"
| search task_command="*AppData*" OR task_command="*\\\\Temp\\\\*" OR task_command="*powershell*"
| table _time host SubjectUserName TaskName task_command""",
        _sigma("Scheduled Task Executing From Suspicious Location", "7b3a9c21-2e5d-4f6a-8c1b-4d2e3f5a6b05",
               "Création de tâche planifiée pointant vers un interpréteur ou un répertoire inscriptible", "process_creation",
               "    selection:\n        Image|endswith: '\\schtasks.exe'\n        CommandLine|contains: '/create'\n"
               "    suspicious:\n        CommandLine|contains:\n            - 'powershell'\n            - '\\AppData\\'\n"
               "            - '\\Temp\\'\n            - 'mshta'\n    condition: selection and suspicious",
               ["Installeurs logiciels légitimes"], "medium", ["attack.persistence", "attack.t1053.005"]),
        "Tâches rares, créées par des processus inhabituels ou pointant vers des chemins utilisateur.",
        "Exporter la définition de la tâche, analyser le binaire ciblé, vérifier le créateur.",
        ["Inventorier régulièrement les tâches planifiées", "Alerter sur 4698 hors processus de déploiement"],
        ["T1053.005"], ["R-PER-002"]),
    Hypothesis(
        "H-06", "Unauthorized KMS Activators",
        "Détecter les activateurs de licences illégitimes (KMSPico, KMSAuto…) et leurs effets.",
        "Des postes exécutent un activateur KMS non autorisé, souvent associé à des exclusions antivirus.",
        ["Fichiers/processus KMSPico, AutoPico, KMSAuto", "Service KMSELDI", "Tâche « AutoPico Daily Restart »",
         "Add-MpPreference -ExclusionPath"],
        ["DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents", "SecurityEvent 7045/4698"],
        """union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName has_any ("KMSpico", "AutoPico", "KMSAuto", "AutoKMS", "SECOH-QAD", "KMSELDI")
    or FolderPath has_any ("KMSpico", "KMSAuto")
    or ProcessCommandLine has_any ("KMSpico", "AutoPico", "KMSAuto")
| summarize Events = count(), Files = make_set(FileName, 20) by DeviceName
| order by Events desc""",
        """index=wineventlog (sourcetype="XmlWinEventLog:Security" OR sourcetype="XmlWinEventLog:System")
    ("KMSpico" OR "AutoPico" OR "KMSAuto" OR "KMSELDI" OR "SECOH-QAD")
| stats count values(EventCode) as event_codes by host""",
        _sigma("KMS Activator Execution", "1d6e8f30-5a7b-4c9d-b2e1-7f3a4c5d6e06",
               "Exécution d'un activateur de licence KMS non autorisé", "process_creation",
               "    selection:\n        - Image|contains:\n            - 'KMSpico'\n            - 'AutoPico'\n            - 'KMSAuto'\n"
               "        - CommandLine|contains:\n            - 'KMSpico'\n            - 'AutoPico'\n    condition: selection",
               ["Aucun dans un parc licencié"], "medium", ["attack.persistence"]),
        "Postes hébergeant des activateurs ; vérifier les exclusions antivirus ajoutées.",
        "Confirmer l'installation, lister les exclusions Defender, rechercher d'éventuels malwares associés.",
        ["Désinstaller et supprimer les exclusions", "Bloquer via WDAC/AppLocker", "Rappeler la politique de licences"],
        ["T1685", "T1053.005", "T1543.003"], ["R-PUA-001"]),
    Hypothesis(
        "H-07", "Suspicious USB Execution",
        "Identifier l'exécution de programmes depuis des supports amovibles.",
        "Un malware se propage ou est introduit via une clé USB.",
        ["Montage d'un périphérique USB", "Exécution depuis un lecteur autre que C:", "Double extension (.pdf.exe)"],
        ["DeviceEvents (UsbDriveMounted)", "DeviceProcessEvents", "Sysmon EID 1"],
        """let usb = DeviceEvents
| where Timestamp > ago(7d) and ActionType == "UsbDriveMounted"
| extend DriveLetter = tostring(parse_json(AdditionalFields).DriveLetter)
| project UsbTime = Timestamp, DeviceName, DriveLetter;
DeviceProcessEvents
| where Timestamp > ago(7d)
| extend Drive = substring(FolderPath, 0, 2)
| join kind=inner usb on DeviceName
| where Drive =~ DriveLetter and Timestamp between (UsbTime .. (UsbTime + 4h))
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| regex Image="^[D-Zd-z]:\\\\\\\\"
| stats count by host Image User""",
        _sigma("Process Executed From Removable Drive Letter", "3e9b7a12-6c4d-4e8f-a1b2-8d5c6e7f8a07",
               "Exécution d'un processus depuis une lettre de lecteur amovible", "process_creation",
               "    selection:\n        Image|re: '^[D-Zd-z]:\\\\'\n    filter_dvd:\n        Image|startswith: 'D:\\Program Files'\n"
               "    condition: selection and not filter_dvd",
               ["Lecteurs de données secondaires fixes (à exclure par lettre)"], "medium",
               ["attack.initial-access", "attack.t1091"]),
        "Exécutions depuis des lettres de lecteurs amovibles peu après un montage USB.",
        "Identifier le périphérique (VID/PID/numéro de série), le fichier exécuté et les autres hôtes où il a été branché.",
        ["Bloquer l'exécution depuis les supports amovibles (Device Control/GPO)"], ["T1091"], ["R-USB-001", "R-USB-002"]),
    Hypothesis(
        "H-08", "Brute Force",
        "Détecter les tentatives répétées d'authentification sur un même compte.",
        "Un attaquant tente de deviner le mot de passe d'un compte exposé.",
        ["Nombreux échecs (4625/LogonFailed) pour un compte", "Succès après échecs depuis la même source"],
        ["DeviceLogonEvents", "SecurityEvent 4625/4624", "Journaux sshd"],
        """DeviceLogonEvents
| where Timestamp > ago(1d)
| summarize Failures = countif(ActionType == "LogonFailed"), Successes = countif(ActionType == "LogonSuccess"),
    Accounts = dcount(AccountName) by RemoteIP, DeviceName, bin(Timestamp, 15m)
| where Failures >= 10
| order by Failures desc""",
        """index=wineventlog sourcetype="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| bin _time span=15m
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes dc(TargetUserName) as accounts
    by _time IpAddress host
| where failures>=10""",
        _sigma_corr("Multiple Failed Logons From Single Source", "6a2c8e40-9b1d-4f3e-b7a6-2c4d5e6f7a08",
                    "6a2c8e40-9b1d-4f3e-b7a6-2c4d5e6f7a18", "failed_logon_h08",
                    "Nombreux échecs d'ouverture de session depuis une même source",
                    "    selection:\n        EventID: 4625\n    condition: selection", "IpAddress", "15m", 10, "medium",
                    ["attack.credential-access", "attack.t1110.001"], ["Mot de passe obsolète enregistré sur un appareil"]),
        "Sources avec de nombreux échecs ; prioriser celles suivies d'un succès.",
        "Vérifier la légitimité de la source, l'éventuel succès et l'activité qui suit.",
        ["MFA, verrouillage intelligent, restriction des expositions (RDP/SSH)"], ["T1110.001", "T1078"], ["R-AUTH-001"]),
    Hypothesis(
        "H-09", "Password Spraying",
        "Détecter quelques mots de passe testés sur de nombreux comptes.",
        "Un attaquant teste un mot de passe courant sur de nombreux comptes pour éviter le verrouillage.",
        ["Échecs sur ≥ 5 comptes distincts depuis une même source", "Succès ultérieur sur l'un des comptes"],
        ["SigninLogs (Entra ID)", "SecurityEvent 4625/4771", "DeviceLogonEvents"],
        """SigninLogs
| where TimeGenerated > ago(1d)
| summarize Failures = countif(ResultType != "0"), Successes = countif(ResultType == "0"),
    Users = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where Users >= 5 and Failures >= 10
| order by Users desc""",
        """index=wineventlog sourcetype="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4771)
| bin _time span=1h
| stats dc(TargetUserName) as accounts count as failures by _time IpAddress
| where accounts>=5""",
        _sigma_corr("Password Spraying Pattern", "8c4e0a60-1d3f-4b5a-9c8e-4e6f7a8b9c09",
                    "8c4e0a60-1d3f-4b5a-9c8e-4e6f7a8b9c19", "failed_logon_h09",
                    "Échecs d'authentification sur de nombreux comptes depuis une même source (seuil de comptes distincts "
                    "à affiner avec une corrélation value_count sur TargetUserName si le backend la prend en charge)",
                    "    selection:\n        EventID:\n            - 4625\n            - 4771\n    condition: selection",
                    "IpAddress", "1h", 20, "high", ["attack.credential-access", "attack.t1110.003"],
                    ["Serveurs relais d'authentification (VPN, proxy)"]),
        "Adresses IP échouant sur de nombreux comptes.",
        "Vérifier les comptes ayant réussi après les échecs ; forcer leur réinitialisation.",
        ["Bloquer l'authentification héritée", "Politique de mots de passe interdits"], ["T1110.003"], ["R-AUTH-001"]),
    Hypothesis(
        "H-10", "Lateral Movement",
        "Identifier l'exécution à distance entre hôtes internes.",
        "Un attaquant utilise des identifiants volés pour exécuter du code à distance (PsExec, WMI, WinRM).",
        ["Service PSEXESVC / création de service à distance", "wmic /node process call create",
         "Processus enfants de WmiPrvSE ou wsmprovhost", "Ouvertures de session réseau privilégiées"],
        ["DeviceProcessEvents", "DeviceLogonEvents", "SecurityEvent 4624 type 3/10, 7045"],
        """DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe") and FileName in~ ("powershell.exe", "cmd.exe"))
    or FileName in~ ("psexesvc.exe", "paexec.exe")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:" and ProcessCommandLine has "call create")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine""",
        """index=wineventlog sourcetype="XmlWinEventLog:System" EventCode=7045
    (ServiceName="PSEXESVC" OR ImagePath="*\\\\ADMIN$\\\\*" OR ImagePath="*cmd.exe /c*")
| table _time host ServiceName ImagePath""",
        _sigma("Remote Execution Via WMI Or WinRM Child Process", "2f6a8c80-3e5b-4d7c-8a9f-6b7c8d9e0f10",
               "Interpréteur lancé par WmiPrvSE ou wsmprovhost", "process_creation",
               "    selection:\n        ParentImage|endswith:\n            - '\\WmiPrvSE.exe'\n            - '\\wsmprovhost.exe'\n"
               "        Image|endswith:\n            - '\\powershell.exe'\n            - '\\cmd.exe'\n    condition: selection",
               ["Outils d'administration à distance autorisés"], "medium",
               ["attack.lateral-movement", "attack.t1047", "attack.t1021.006"]),
        "Exécutions à distance inhabituelles entre postes de travail.",
        "Identifier le poste source et le compte, reconstituer la propagation.",
        ["Restreindre les partages administratifs et WinRM", "LAPS et segmentation"],
        ["T1021.002", "T1047", "T1021.006"], ["R-LAT-001", "R-LAT-002", "R-LAT-003", "R-LAT-004", "R-LAT-005"]),
    Hypothesis(
        "H-11", "Suspicious DNS Queries",
        "Détecter les DGA et le tunneling DNS.",
        "Un implant résout des domaines pseudo-aléatoires ou encode des données dans des sous-domaines.",
        ["Nombreux NXDOMAIN", "Labels longs à forte entropie", "Volume élevé vers un même domaine parent"],
        ["DnsEvents (Sentinel)", "DeviceNetworkEvents/DeviceEvents DnsQueryResponse", "Sysmon EID 22"],
        """DeviceEvents
| where Timestamp > ago(1d) and ActionType == "DnsQueryResponse"
| extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)
| extend Label = tostring(split(Query, ".")[0])
| where strlen(Label) >= 20
| summarize Queries = count(), Samples = make_set(Query, 10) by DeviceName, Parent = strcat(tostring(split(Query, ".")[-2]), ".", tostring(split(Query, ".")[-1]))
| where Queries > 20""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| eval label=mvindex(split(QueryName,"."),0), label_len=len(label)
| where label_len>=20 OR QueryStatus="9003"
| stats count dc(QueryName) as distinct_queries by host Image
| where distinct_queries>20""",
        _sigma("Long Random DNS Labels", "4b8c0e90-5f7a-4e9b-9c0d-8e9f0a1b2c11", "Requêtes DNS avec labels longs",
               "dns_query", "    selection:\n        QueryName|re: '^[a-z0-9]{25,}\\.'\n    condition: selection",
               ["CDN et services cloud utilisant des sous-domaines longs"], "medium",
               ["attack.command-and-control", "attack.t1568.002", "attack.t1071.004"]),
        "Hôtes générant de nombreuses résolutions anormales.",
        "Identifier le processus émetteur et la réputation du domaine parent.",
        ["DNS filtrant / sinkhole", "Journalisation DNS centralisée"], ["T1568.002", "T1071.004"], ["R-DNS-001", "R-DNS-002"]),
    Hypothesis(
        "H-12", "Persistence Through Registry",
        "Détecter les modifications de clés de démarrage automatique.",
        "Un attaquant ajoute une valeur Run/RunOnce ou modifie Winlogon pour persister.",
        ["Écriture dans ...\\CurrentVersion\\Run(Once)", "Modification de Winlogon Shell/Userinit",
         "Valeur pointant vers AppData/Temp ou un interpréteur"],
        ["DeviceRegistryEvents", "Sysmon EID 13"],
        """DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\\CurrentVersion\\Run", @"\\Winlogon")
| where RegistryValueData has_any ("AppData", "\\\\Temp\\\\", "ProgramData", "powershell", "mshta", "rundll32", "wscript")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    (TargetObject="*\\\\CurrentVersion\\\\Run*" OR TargetObject="*\\\\Winlogon\\\\*")
| table _time host Image TargetObject Details""",
        _sigma("Run Key Pointing To Suspicious Location", "6d0e2f10-7a9b-4c1d-8e2f-0a1b2c3d4e12",
               "Clé Run modifiée vers un chemin inscriptible ou un interpréteur", "registry_set",
               "    selection:\n        TargetObject|contains: '\\CurrentVersion\\Run'\n        Details|contains:\n"
               "            - '\\AppData\\'\n            - '\\Temp\\'\n            - 'powershell'\n    condition: selection",
               ["Applications installées par utilisateur"], "medium", ["attack.persistence", "attack.t1547.001"]),
        "Valeurs rares, ajoutées par des processus non installateurs.",
        "Analyser le binaire ciblé et le processus ayant écrit la valeur.",
        ["Audit régulier des ASEP (Autoruns)"], ["T1547.001"], ["R-PER-001"]),
    Hypothesis(
        "H-13", "Malicious Hash Execution",
        "Rechercher l'exécution de fichiers dont le hash est connu comme malveillant.",
        "Des fichiers identifiés lors d'une investigation ou par la CTI ont été exécutés ailleurs sur le parc.",
        ["Exécution ou création d'un fichier dont le SHA256 figure dans la liste d'IOC"],
        ["DeviceProcessEvents", "DeviceFileEvents", "Sysmon EID 1/11 (Hashes)"],
        """let iocs = dynamic(["<SHA256_1>", "<SHA256_2>"]);  // À remplacer par les hashs de l'investigation
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (iocs)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName""",
        """index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=11)
    (Hashes="*<SHA256_1>*" OR Hashes="*<SHA256_2>*")
| table _time host Image TargetFilename Hashes""",
        _sigma("Execution Of Known Malicious Hash", "8f2a4b30-9c1d-4e3f-a5b6-2c3d4e5f6a13",
               "Exécution d'un fichier dont le hash figure dans les IOC", "process_creation",
               "    selection:\n        Hashes|contains:\n            - '<SHA256_1>'\n    condition: selection",
               ["Aucun si les IOC sont validés"], "high", ["attack.execution", "attack.t1204.002"]),
        "Tout résultat indique une présence du fichier : périmètre de l'incident élargi.",
        "Confirmer l'exécution, contenir les hôtes, analyser l'origine du fichier.",
        ["Ajouter les hashs validés en blocage dans l'EDR"], ["T1204.002"], ["R-STA-001", "R-EXE-001"]),
]


def get(hid: str) -> Hypothesis | None:
    return next((h for h in HYPOTHESES if h.hid == hid), None)


def queries_for_rules(rules: set[str]) -> list[dict]:
    out = []
    for h in HYPOTHESES:
        if rules & set(h.rules):
            out.append({"language": "KQL", "purpose": f"{h.name} – recherche étendue sur le parc", "query": h.kql})
            out.append({"language": "SPL", "purpose": f"{h.name} – équivalent Splunk", "query": h.spl})
    return out


def with_iocs(h: Hypothesis, sha256s: list[str]) -> Hypothesis:
    """Instancie H-13 avec les hashs réels d'une investigation (sans modifier la bibliothèque)."""
    if h.hid != "H-13" or not sha256s:
        return h
    lst = ", ".join(f'"{x}"' for x in sha256s[:50])
    spl_terms = " OR ".join(f'Hashes="*{x}*"' for x in sha256s[:50])
    sigma_terms = "\n".join(f"            - '{x}'" for x in sha256s[:50])
    import copy

    h2 = copy.deepcopy(h)
    h2.kql = h.kql.replace('dynamic(["<SHA256_1>", "<SHA256_2>"]);  // À remplacer par les hashs de l\'investigation',
                           f"dynamic([{lst}]);")
    h2.spl = h.spl.replace('(Hashes="*<SHA256_1>*" OR Hashes="*<SHA256_2>*")', f"({spl_terms})")
    h2.sigma = h.sigma.replace("            - '<SHA256_1>'", sigma_terms)
    return h2
