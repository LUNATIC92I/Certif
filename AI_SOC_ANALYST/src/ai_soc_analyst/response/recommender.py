"""Recommandations de réponse à incident.

IMPORTANT : ce module ne fait que PROPOSER des actions. Aucune action n'est exécutée sur l'environnement :
l'analyste les approuve ou les rejette, puis les réalise lui-même dans ses outils (EDR, IAM, pare-feu).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

ACTION_CATALOG = {
    "Isolate Endpoint": dict(
        objective="Couper les communications réseau de l'hôte pour stopper la propagation et le C2, tout en conservant la "
                  "connexion à la console EDR pour l'investigation.",
        risk="Interruption de service si l'hôte est un serveur de production ; possible alerte de l'attaquant.",
        impact="L'utilisateur ou le service hébergé perd l'accès réseau jusqu'à la levée de l'isolement.",
        prerequisites="EDR déployé et en ligne sur l'hôte ; validation du responsable métier pour un serveur ; "
                      "exceptions réseau prévues si des outils d'investigation doivent rester joignables.",
        procedure="1. Vérifier l'impact métier. 2. Isoler depuis la console EDR (Defender : « Isolate device », "
                  "CrowdStrike : « Network contain », etc.). 3. Collecter les preuves volatiles. 4. Documenter l'heure et "
                  "l'auteur de l'action. 5. Lever l'isolement après éradication validée."),
    "Block Malicious Hash": dict(
        objective="Empêcher toute nouvelle exécution du fichier identifié sur le parc.",
        risk="Faible ; risque de blocage d'un fichier légitime si le hash est mal qualifié.",
        impact="Le fichier ne peut plus s'exécuter sur les postes protégés.",
        prerequisites="Hash SHA256 confirmé comme malveillant ou indésirable par l'investigation.",
        procedure="Ajouter le SHA256 en indicateur « Block » dans l'EDR (Defender : Indicators > File hashes ; "
                  "CrowdStrike : IOC Management), puis rechercher rétroactivement les exécutions sur le parc."),
    "Block IP Address": dict(
        objective="Empêcher les communications avec l'adresse externe impliquée (C2, téléchargement, attaque).",
        risk="Blocage d'un service légitime si l'adresse est partagée (CDN, hébergeur mutualisé).",
        impact="Connexions vers/depuis l'adresse refusées au périmètre et/ou sur les endpoints.",
        prerequisites="Adresse publique liée aux preuves ; vérification qu'il ne s'agit pas d'une infrastructure partagée.",
        procedure="Ajouter une règle de blocage sur le pare-feu périmétrique / proxy et un indicateur réseau dans l'EDR ; "
                  "définir une date d'expiration et une revue."),
    "Block Domain": dict(
        objective="Bloquer la résolution et l'accès au domaine impliqué.",
        risk="Faible si le domaine est spécifique à l'attaquant ; élevé pour un domaine partagé.",
        impact="Requêtes DNS/HTTP vers le domaine refusées.",
        prerequisites="Domaine lié aux preuves de l'incident.",
        procedure="Ajouter le domaine au DNS sinkhole / filtrage web / indicateurs EDR, puis rechercher les autres hôtes "
                  "l'ayant contacté."),
    "Disable Compromised Account": dict(
        objective="Empêcher l'attaquant d'utiliser le compte compromis.",
        risk="Interruption du travail de l'utilisateur ou d'une application (compte de service).",
        impact="Le compte ne peut plus s'authentifier.",
        prerequisites="Preuves d'usage malveillant du compte ; coordination avec le propriétaire du compte/application.",
        procedure="Désactiver le compte dans l'annuaire (AD / Entra ID), puis révoquer les sessions et planifier la "
                  "réinitialisation des secrets."),
    "Revoke Sessions": dict(
        objective="Invalider les sessions et jetons existants du compte.",
        risk="Faible ; l'utilisateur doit se réauthentifier.",
        impact="Déconnexion des sessions en cours.",
        prerequisites="Compte identifié ; accès administrateur IAM.",
        procedure="Entra ID : « Revoke sessions » ; AD : réinitialiser le mot de passe deux fois si des tickets Kerberos "
                  "sont suspectés ; vérifier ensuite les méthodes MFA enregistrées."),
    "Reset Password": dict(
        objective="Rendre inutilisables les identifiants potentiellement volés.",
        risk="Faible ; attention aux comptes de service (dépendances applicatives).",
        impact="L'utilisateur ou l'application doit utiliser le nouveau mot de passe.",
        prerequisites="Canal sûr pour transmettre le nouveau secret ; inventaire des dépendances pour un compte de service.",
        procedure="Réinitialiser via l'annuaire, imposer un changement à la prochaine connexion et vérifier l'absence de "
                  "réutilisation sur d'autres services."),
    "Remove Persistence": dict(
        objective="Supprimer les mécanismes permettant à l'attaquant de revenir (clé Run, tâche, service, WMI).",
        risk="Suppression d'un élément légitime si mal identifié.",
        impact="Faible si l'élément est bien malveillant.",
        prerequisites="Preuve collectée (export de la clé, définition de la tâche/service, binaire ciblé).",
        procedure="Documenter l'élément, collecter le binaire ciblé, supprimer l'élément via l'EDR (réponse à distance) "
                  "ou les outils d'administration, puis vérifier son absence et chasser le même élément sur le parc."),
    "Quarantine File": dict(
        objective="Neutraliser le fichier malveillant présent sur le disque.",
        risk="Faible ; réversible depuis la console EDR.",
        impact="Le fichier est déplacé en quarantaine et ne peut plus être exécuté.",
        prerequisites="Chemin et hash du fichier identifiés.",
        procedure="Mettre le fichier en quarantaine depuis l'EDR et conserver une copie pour analyse dans un environnement isolé."),
    "Collect Additional Evidence": dict(
        objective="Compléter les données manquantes pour confirmer ou infirmer les hypothèses.",
        risk="Nul pour l'environnement ; consomme du temps d'analyse.",
        impact="Aucun.",
        prerequisites="Accès aux sources indiquées (EDR, SIEM, journaux, mémoire).",
        procedure="Collecter les éléments listés dans la justification (journaux, télémétrie, image mémoire, échantillon) en "
                  "documentant les hashs et la chaîne de possession."),
    "Escalate Incident": dict(
        objective="Transférer l'incident au niveau supérieur (L2/L3, CSIRT, direction) selon la matrice d'escalade.",
        risk="Nul ; un retard d'escalade augmente l'impact.",
        impact="Mobilisation d'équipes supplémentaires.",
        prerequisites="Rapport d'investigation à jour.",
        procedure="Notifier selon la matrice d'escalade avec le rapport technique, les preuves et les actions déjà menées."),
}


@dataclass
class ActionProposal:
    action_type: str
    target: str
    justification: str
    priority: str
    evidence_ids: list[str] = field(default_factory=list)
    objective: str = ""
    risk: str = ""
    impact: str = ""
    prerequisites: str = ""
    procedure: str = ""

    def __post_init__(self):
        meta = ACTION_CATALOG[self.action_type]
        for k in ("objective", "risk", "impact", "prerequisites", "procedure"):
            if not getattr(self, k):
                setattr(self, k, meta[k])

    def to_dict(self) -> dict:
        return asdict(self)


def recommend(findings: list, iocs: list, verdict: str, severity: str, triage: dict, limitations: list[str]) -> list[dict]:
    props: list[ActionProposal] = []
    active = [f for f in findings if f.status in ("Confirmed", "Likely")]
    seen: set[tuple[str, str]] = set()

    def add(kind: str, target: str, why: str, prio: str, evids: list[str]) -> None:
        key = (kind, target.lower())
        if key not in seen:
            seen.add(key)
            props.append(ActionProposal(kind, target, why, prio, sorted(set(evids))[:20]))

    hosts = sorted({h for h in triage.get("hosts", []) if h})
    rules = {f.rule_id for f in active}
    if active and hosts and (rules & {"R-RAN-001", "R-RAN-003", "R-CRD-001", "R-CRD-002", "R-NET-002", "R-NET-001",
                                       "R-DLL-001", "R-LAT-001", "R-LNX-001", "R-ALR-001", "R-PS-001", "R-OFF-001",
                                       "R-INJ-001", "R-USB-001"}):
        for f in active:
            for h in f.details.get("hosts", []) or hosts[:3]:
                add("Isolate Endpoint", h, f"{f.finding_id} – {f.title} ({f.status}).",
                    "Critical" if f.severity == "Critical" else "High", f.evidence_ids)
    for ioc in iocs:
        if ioc.risk not in ("High", "Critical", "Medium") or ioc.validation_status == "Non validé":
            continue
        why = f"Indicateur lié aux détections : {ioc.justification}"
        if ioc.ioc_type == "sha256":
            add("Block Malicious Hash", ioc.value, why, "High", ioc.evidence_ids)
            add("Quarantine File", ioc.value, why, "High", ioc.evidence_ids)
        elif ioc.ioc_type in ("ipv4", "ipv6") and "publique" in ioc.justification:
            add("Block IP Address", ioc.value, why, "Medium", ioc.evidence_ids)
        elif ioc.ioc_type == "domain" and "éditeur connu" not in ioc.justification:
            add("Block Domain", ioc.value, why, "Medium", ioc.evidence_ids)
    for f in active:
        if f.rule_id in ("R-PER-001", "R-PER-002", "R-PER-003", "R-PRV-001"):
            add("Remove Persistence", f.title, f"{f.finding_id} : {f.description[:200]}", "High", f.evidence_ids)
        if f.rule_id in ("R-AUTH-001", "R-CRD-001", "R-CRD-002", "R-ACC-002") or "T1078" in f.mitre_ids:
            users = f.details.get("users") or [u for u in triage.get("users", [])][:3]
            for u in users:
                if f.rule_id == "R-AUTH-001" and "T1078" not in f.mitre_ids:
                    add("Reset Password", u, f"{f.finding_id} : compte ciblé par des tentatives répétées.", "Medium", f.evidence_ids)
                    continue
                add("Disable Compromised Account", u, f"{f.finding_id} : {f.title}.", "High", f.evidence_ids)
                add("Revoke Sessions", u, f"{f.finding_id} : identifiants potentiellement exposés.", "High", f.evidence_ids)
                add("Reset Password", u, f"{f.finding_id} : identifiants potentiellement exposés.", "High", f.evidence_ids)
        if f.rule_id == "R-PUA-001":
            add("Remove Persistence", "Activateur KMS et éléments associés",
                f"{f.finding_id} : logiciel non autorisé à désinstaller ; vérifier les exclusions antivirus ajoutées.",
                "Medium", f.evidence_ids)
    if verdict in ("Confirmed", "Likely") and severity in ("Critical", "High"):
        add("Escalate Incident", "Niveau 2/3 – CSIRT", f"Verdict {verdict}, sévérité {severity}.",
            "Critical" if severity == "Critical" else "High", [])
    if limitations or verdict in ("Suspicious", "Inconclusive"):
        add("Collect Additional Evidence", "Sources complémentaires",
            "Limites identifiées : " + "; ".join(limitations[:4]) if limitations else
            "Qualification incomplète : données complémentaires nécessaires.", "Medium", [])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    props.sort(key=lambda p: (order.get(p.priority, 9), p.action_type))
    return [p.to_dict() for p in props]
