"""Chargement des questions sources, équilibrage des réponses et textes communs."""
import random
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent
DATA = SRC / "data"

DIFF_LABEL = {"F": "Fondamental", "I": "Intermédiaire", "A": "Avancé / Expert"}
DIFF_ORDER = {"F": 0, "I": 1, "A": 2}
LETTERS = "ABCD"
SEED = 2026

MODULE_FILES = [f"m{i:02d}.txt" for i in range(1, 11)]

# Correspondance avec les domaines du programme CSA v2 (312-39)
CSA_MAPPING = [
    ("Module 1 – SOC Fundamentals", "D1 Security Operations and Management"),
    ("Module 2 – SIEM and Log Management", "D3 Log Management ; D4 Incident Detection and Triage"),
    ("Module 3 – Network Security Monitoring", "D2 Cyber Threats, IoCs and Attack Methodology ; D4 Incident Detection and Triage"),
    ("Module 4 – Threat Intelligence", "D5 Proactive Threat Detection"),
    ("Module 5 – Incident Detection and Response", "D4 Incident Detection and Triage ; D6 Incident Response ; D7 Forensic Investigation"),
    ("Module 6 – Endpoint Security and Malware Analysis", "D3 Log Management ; D7 Forensic Investigation and Malware Analysis"),
    ("Module 7 – Vulnerability Management and Attack Techniques", "D2 Cyber Threats, IoCs and Attack Methodology"),
    ("Module 8 – Threat Hunting and Detection Engineering", "D5 Proactive Threat Detection ; D4 Incident Detection and Triage"),
    ("Module 9 – Cloud Security and Identity Monitoring", "D8 SOC for Cloud Environments"),
    ("Module 10 – SOC Reporting and Operational Excellence", "D1 Security Operations and Management ; D6 Incident Response"),
]

CSA_DOMAINS = [
    ("1", "Security Operations and Management", "5 %"),
    ("2", "Understanding Cyber Threats, IoCs, and Attack Methodology", "8 %"),
    ("3", "Log Management", "15 %"),
    ("4", "Incident Detection and Triage", "25 %"),
    ("5", "Proactive Threat Detection", "12 %"),
    ("6", "Incident Response", "25 %"),
    ("7", "Forensic Investigation and Malware Analysis", "5 %"),
    ("8", "SOC for Cloud Environments", "5 %"),
]

SCORE_LEVELS = [
    ("90 – 100", "Excellent niveau de préparation", "Vous maîtrisez le programme. Entretenez vos acquis et passez l'examen dans de bonnes conditions."),
    ("80 – 89", "Très bon niveau", "Ciblez les quelques domaines où subsistent des erreurs, puis refaites la simulation."),
    ("70 – 79", "Niveau satisfaisant, quelques révisions nécessaires", "Reprenez les explications des questions manquées et les modules correspondants de la banque."),
    ("60 – 69", "Préparation insuffisante", "Retravaillez les modules les plus faibles, notamment la détection, le triage et la réponse aux incidents."),
    ("< 60", "Révisions approfondies recommandées", "Reprenez la banque de 200 questions module par module avant une nouvelle simulation."),
]

BIBLIO = [
    ("EC-Council – Certified SOC Analyst (page officielle du programme)", "https://www.eccouncil.org/train-certify/certified-soc-analyst-csa/"),
    ("EC-Council – Brochure CSA (2025)", "https://pitman.eccouncil.org/wp-content/uploads/2025/01/CSA-Brochure.pdf"),
    ("EC-Council – CSA v1 Exam Blueprint (version historique)", "https://cert.eccouncil.org/images/doc/CSAv1-Exam-Blueprint.pdf"),
    ("Fast Lane – Plan de cours EC-Council CSA (8 modules)", "https://www.flane.co.uk/course-outline/ec-csa"),
    ("A Guide to Cloud – Fiche examen 312-39 CSA v2 (domaines et pondérations)", "https://www.aguidetocloud.com/cert-tracker/eccouncil-csa/"),
    ("MITRE ATT&CK – Enterprise Matrix", "https://attack.mitre.org/"),
    ("NIST SP 800-61 Rev. 2 – Computer Security Incident Handling Guide", "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("NIST SP 800-61 Rev. 3 – Incident Response Recommendations (CSF 2.0)", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
    ("NIST Cybersecurity Framework 2.0", "https://www.nist.gov/cyberframework"),
    ("RFC 3227 – Guidelines for Evidence Collection and Archiving", "https://www.rfc-editor.org/rfc/rfc3227"),
    ("RFC 5424 – The Syslog Protocol", "https://www.rfc-editor.org/rfc/rfc5424"),
    ("FIRST – Traffic Light Protocol 2.0", "https://www.first.org/tlp/"),
    ("FIRST – CVSS v3.1 et v4.0", "https://www.first.org/cvss/"),
    ("FIRST – EPSS", "https://www.first.org/epss/"),
    ("CISA – Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("OASIS – STIX / TAXII", "https://oasis-open.github.io/cti-documentation/"),
    ("Microsoft Learn – Microsoft Sentinel", "https://learn.microsoft.com/azure/sentinel/"),
    ("Microsoft Learn – Advanced hunting (Defender XDR)", "https://learn.microsoft.com/defender-xdr/advanced-hunting-overview"),
    ("Microsoft Learn – Kusto Query Language (KQL)", "https://learn.microsoft.com/kusto/query/"),
    ("Microsoft Learn – Codes d'erreur Entra ID (AADSTS)", "https://learn.microsoft.com/entra/identity-platform/reference-error-codes"),
    ("Microsoft Sysinternals – Sysmon", "https://learn.microsoft.com/sysinternals/downloads/sysmon"),
    ("Splunk Documentation (SPL, Enterprise Security, CIM)", "https://docs.splunk.com/"),
    ("IBM QRadar Documentation", "https://www.ibm.com/docs/en/qradar-common"),
    ("Elastic Common Schema (ECS)", "https://www.elastic.co/guide/en/ecs/current/index.html"),
    ("CrowdStrike – Falcon Platform", "https://www.crowdstrike.com/platform/"),
    ("SigmaHQ – Sigma rules", "https://github.com/SigmaHQ/sigma"),
    ("LOLBAS Project", "https://lolbas-project.github.io/"),
    ("SOC-CMM – SOC Capability Maturity Model", "https://www.soc-cmm.com/"),
    ("D. Bianco – The Pyramid of Pain", "https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html"),
    ("Lockheed Martin – Cyber Kill Chain", "https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html"),
    ("Règlement (UE) 2016/679 – RGPD", "https://eur-lex.europa.eu/eli/reg/2016/679/oj"),
]

DISCLAIMER = (
    "Ce document contient exclusivement des questions d'entraînement originales, rédigées à partir "
    "des domaines de compétences publiés pour la certification Certified SOC Analyst (CSA) et de la "
    "documentation technique de référence (MITRE ATT&CK, NIST, Microsoft Learn, éditeurs SIEM/EDR). "
    "Il ne s'agit en aucun cas de questions réelles, confidentielles ou divulguées de l'examen EC-Council. "
    "Ce guide n'est ni affilié, ni approuvé par EC-Council. CSA et Certified SOC Analyst sont des marques "
    "d'EC-Council."
)

EXAM_INFO = [
    ("Code d'examen", "312-39"),
    ("Version du programme", "CSA v2 (la v1 a été retirée en 2026 selon les sources tierces consultées)"),
    ("Format", "100 questions à choix multiples"),
    ("Durée", "3 heures"),
    ("Seuil de réussite", "70 % (peut varier selon la forme d'examen)"),
    ("Modalité", "ECC Exam Portal (en ligne surveillé) ou centre agréé"),
]


def parse_file(path):
    module_title = None
    questions = []
    cur = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("# "):
            module_title = line[2:].strip()
            continue
        if line.startswith("## "):
            if cur:
                questions.append(cur)
            diff, skill = line[3:].split("|", 1)
            cur = {"diff": diff.strip(), "skill": skill.strip(), "q": [], "good": None,
                   "bad": [], "exp": []}
            continue
        if cur is None or not line.strip():
            continue
        if line.startswith("+ "):
            cur["good"] = line[2:].strip()
        elif line.startswith("- "):
            cur["bad"].append(line[2:].strip())
        elif line.startswith("> "):
            cur["exp"].append(line[2:].strip())
        else:
            cur["q"].append(line.strip())
    if cur:
        questions.append(cur)
    for q in questions:
        q["q"] = " ".join(q["q"])
        q["exp"] = " ".join(q["exp"])
        assert q["good"] and len(q["bad"]) == 3, (path, q["q"][:60])
        assert q["diff"] in DIFF_LABEL, (path, q["diff"])
    return module_title, questions


def _balanced_positions(n, rng):
    pos = []
    while len(pos) < n:
        block = [0, 1, 2, 3]
        rng.shuffle(block)
        pos.extend(block)
    return pos[:n]


def _finalize(raw, positions, rng, prefix, width):
    out = []
    for i, (q, p) in enumerate(zip(raw, positions), start=1):
        bad = q["bad"][:]
        rng.shuffle(bad)
        opts = bad[:p] + [q["good"]] + bad[p:]
        out.append({
            "id": f"{prefix}{i:0{width}d}",
            "numero": i,
            "module": q["module"],
            "module_titre": q["module_title"],
            "difficulte": DIFF_LABEL[q["diff"]],
            "difficulte_code": q["diff"],
            "question": q["q"],
            "choix": {LETTERS[k]: opts[k] for k in range(4)},
            "reponse": LETTERS[p],
            "explication": q["exp"],
            "competence": q["skill"] + ".",
        })
    return out


def load_all():
    rng = random.Random(SEED)
    bank_raw, modules = [], []
    for idx, fname in enumerate(MODULE_FILES, start=1):
        title, qs = parse_file(DATA / fname)
        # progression de difficulté à l'intérieur de chaque module
        qs.sort(key=lambda q: DIFF_ORDER[q["diff"]])
        pretty = CSA_MAPPING[idx - 1][0].split(" – ", 1)[1]
        modules.append({"numero": idx, "titre": pretty, "nb": len(qs)})
        for q in qs:
            q["module"] = idx
            q["module_title"] = pretty
        bank_raw.extend(qs)
    _, exam_raw = parse_file(DATA / "exam.txt")
    for q in exam_raw:
        q["module"] = 0
        q["module_title"] = "Simulation d'examen"
    # ordre mélangé (domaines et niveaux), comme lors d'un examen réel
    random.Random(SEED + 1).shuffle(exam_raw)
    bank = _finalize(bank_raw, _balanced_positions(len(bank_raw), rng), rng, "Q", 3)
    exam = _finalize(exam_raw, _balanced_positions(len(exam_raw), rng), rng, "E", 2)
    return modules, bank, exam
