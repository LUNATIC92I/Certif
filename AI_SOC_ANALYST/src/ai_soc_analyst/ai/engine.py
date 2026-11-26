"""AI Investigation Engine.

Fournisseurs : moteur local déterministe (par défaut, hors ligne), OpenAI, Anthropic Claude, Azure OpenAI, Ollama.

Garde-fous :
- seules des preuves déjà extraites (événements, findings, IOC) sont transmises, sous forme d'identifiants vérifiables ;
- la réponse doit être un JSON structuré ; chaque affirmation doit citer des evidence_id existants, sinon elle est
  REJETÉE et présentée comme telle à l'analyste ;
- le mode Privacy Protection bloque tout envoi vers un service distant (seul Ollama local reste autorisé).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from ..core.logging_setup import get_logger
from ..core.settings import Settings

log = get_logger("ai")
STATUSES = ("Confirmed", "Likely", "Suspicious", "Inconclusive", "False Positive")

SYSTEM_PROMPT = """Tu es un Senior SOC Analyst (L3) chargé de relire une investigation de sécurité.
Règles impératives :
1. Tu t'appuies EXCLUSIVEMENT sur les preuves fournies (événements EVT-xxxxx, détections F-xxx, IOC listés).
2. Tu n'inventes jamais d'événement, d'IOC, de résultat de réputation, d'horodatage ou d'attribution.
3. Chaque affirmation cite au moins un identifiant de preuve existant dans le champ evidence_ids.
4. Tu qualifies chaque affirmation avec un statut parmi : Confirmed, Likely, Suspicious, Inconclusive, False Positive,
   et un niveau de confiance entre 0 et 1.
5. Si les données sont insuffisantes, tu le dis dans "gaps" et tu proposes des éléments à collecter.
6. Tu réponds en français, uniquement avec un objet JSON valide respectant ce schéma :
{"executive_summary": str,
 "assessments": [{"statement": str, "status": str, "confidence": float, "evidence_ids": [str], "mitre": [str]}],
 "hypotheses": [{"hypothesis": str, "how_to_validate": str, "evidence_ids": [str]}],
 "additional_queries": [{"language": "KQL|SPL|Sigma", "purpose": str, "query": str}],
 "gaps": [str],
 "analyst_questions": [str]}"""


class AIError(Exception):
    pass


@dataclass
class ProviderConfig:
    name: str
    model: str
    api_key: str | None
    endpoint: str = ""
    api_version: str = ""
    timeout: float = 60.0


def is_local_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def build_evidence_package(result: dict, events: list, max_events: int = 60) -> dict:
    """Paquet de preuves minimal : uniquement ce qui est nécessaire, avec les identifiants vérifiables."""
    flagged = {i for f in result.get("findings", []) for i in f.get("evidence_ids", [])}
    chosen = [e for e in events if e.evidence_id in flagged][:max_events]
    if len(chosen) < max_events:
        chosen += [e for e in events if e.evidence_id not in flagged][: max_events - len(chosen)]
    ev_list = [{"id": e.evidence_id, "time": e.timestamp.isoformat() if e.timestamp else e.timestamp_raw,
                "type": e.event_type, "host": e.host, "user": e.user, "process": e.process_name, "parent": e.parent_name,
                "command_line": e.command_line[:600], "dst": f"{e.dst_ip}:{e.dst_port}" if e.dst_ip else "",
                "dns": e.dns_query, "registry": e.registry_key[:200], "file": e.target_file[:200],
                "source": e.source_product} for e in chosen]
    return {
        "triage": {k: result.get("triage", {}).get(k) for k in ("hosts", "users", "ips", "first_seen", "last_seen", "sources")},
        "local_verdict": {k: result.get(k) for k in ("verdict", "confidence", "severity", "incident_type")},
        "findings": [{k: f.get(k) for k in ("finding_id", "title", "status", "confidence", "severity", "description",
                                           "evidence_ids", "mitre_ids")} for f in result.get("findings", [])][:40],
        "iocs": [{k: i.get(k) for k in ("value", "ioc_type", "reputation", "risk", "evidence_ids")}
                 for i in result.get("iocs", [])][:80],
        "mitre": [{k: m.get(k) for k in ("technique_id", "technique_name", "tactic", "evidence_ids")}
                  for m in result.get("mitre", [])],
        "limitations": result.get("limitations", []),
        "events": ev_list,
    }


def _extract_json(text: str) -> dict:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise AIError("La réponse du modèle ne contient pas d'objet JSON.")
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise AIError(f"JSON invalide renvoyé par le modèle : {exc.msg}") from exc


def validate_ai_output(data: dict, allowed_ids: set[str], valid_techniques: set[str] | None = None) -> dict:
    """Conserve uniquement les affirmations étayées par des preuves existantes."""
    kept, rejected = [], []
    for a in data.get("assessments", []) or []:
        if not isinstance(a, dict):
            continue
        ids = [i for i in a.get("evidence_ids", []) if isinstance(i, str)]
        valid = [i for i in ids if i in allowed_ids]
        status = a.get("status") if a.get("status") in STATUSES else None
        try:
            conf = max(0.0, min(1.0, float(a.get("confidence", 0))))
        except (TypeError, ValueError):
            conf = 0.0
        reason = ""
        if not valid:
            reason = "aucune référence à une preuve existante"
        elif len(valid) < len(ids):
            reason = "références inexistantes : " + ", ".join(sorted(set(ids) - set(valid)))
        elif status is None:
            reason = "statut invalide"
        mitre = [t for t in a.get("mitre", []) if isinstance(t, str) and (valid_techniques is None or t in valid_techniques)]
        item = {"statement": str(a.get("statement", ""))[:1500], "status": status or "Inconclusive",
                "confidence": conf, "evidence_ids": valid, "mitre": mitre}
        (rejected if reason else kept).append(item | ({"rejection_reason": reason} if reason else {}))
    hyps = []
    for h in data.get("hypotheses", []) or []:
        if isinstance(h, dict):
            hyps.append({"hypothesis": str(h.get("hypothesis", ""))[:800], "how_to_validate": str(h.get("how_to_validate", ""))[:800],
                         "evidence_ids": [i for i in h.get("evidence_ids", []) if i in allowed_ids],
                         "label": "Hypothèse (non vérifiée)"})
    queries = [q for q in data.get("additional_queries", []) or [] if isinstance(q, dict) and q.get("query")][:10]
    return {"executive_summary": str(data.get("executive_summary", ""))[:3000], "assessments": kept,
            "rejected_assessments": rejected, "hypotheses": hyps, "additional_queries": queries,
            "gaps": [str(g)[:500] for g in data.get("gaps", []) or []][:15],
            "analyst_questions": [str(q)[:500] for q in data.get("analyst_questions", []) or []][:10]}


# ------------------------------------------------------------------ fournisseurs distants

def call_provider(cfg: ProviderConfig, system: str, user: str, transport: httpx.BaseTransport | None = None) -> str:
    timeout = httpx.Timeout(cfg.timeout, connect=10.0)
    with httpx.Client(timeout=timeout, transport=transport) as client:
        try:
            if cfg.name == "openai":
                r = client.post("https://api.openai.com/v1/chat/completions",
                                headers={"Authorization": f"Bearer {cfg.api_key}"},
                                json={"model": cfg.model, "temperature": 0.1, "response_format": {"type": "json_object"},
                                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
            if cfg.name == "azure_openai":
                if not cfg.endpoint:
                    raise AIError("Point de terminaison Azure OpenAI non configuré.")
                url = (f"{cfg.endpoint.rstrip('/')}/openai/deployments/{cfg.model}/chat/completions"
                       f"?api-version={cfg.api_version}")
                r = client.post(url, headers={"api-key": cfg.api_key or ""},
                                json={"temperature": 0.1, "response_format": {"type": "json_object"},
                                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
            if cfg.name == "anthropic":
                r = client.post("https://api.anthropic.com/v1/messages",
                                headers={"x-api-key": cfg.api_key or "", "anthropic-version": "2023-06-01"},
                                json={"model": cfg.model, "max_tokens": 4000, "temperature": 0.1, "system": system,
                                      "messages": [{"role": "user", "content": user}]})
                r.raise_for_status()
                return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")
            if cfg.name == "ollama":
                r = client.post(f"{cfg.endpoint.rstrip('/')}/api/chat",
                                json={"model": cfg.model, "stream": False, "format": "json", "options": {"temperature": 0.1},
                                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
                r.raise_for_status()
                return r.json()["message"]["content"]
        except httpx.TimeoutException as exc:
            raise AIError(f"Délai d'attente dépassé ({cfg.timeout:.0f} s) auprès de {cfg.name}.") from exc
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            hint = {401: "clé API invalide", 403: "accès refusé", 404: "modèle ou point de terminaison introuvable",
                    429: "quota ou limite de débit atteint"}.get(code, "erreur du service")
            raise AIError(f"{cfg.name} a répondu HTTP {code} ({hint}).") from exc
        except httpx.HTTPError as exc:
            raise AIError(f"Erreur réseau vers {cfg.name} : {type(exc).__name__}.") from exc
        except (KeyError, IndexError, ValueError) as exc:
            raise AIError(f"Réponse inattendue de {cfg.name} : {exc}") from exc
    raise AIError(f"Fournisseur inconnu : {cfg.name}")


def provider_config(settings: Settings, secrets) -> ProviderConfig:  # noqa: ANN001
    a = settings.ai
    if a.provider == "openai":
        return ProviderConfig("openai", a.openai_model, secrets.get("openai_api_key"), timeout=a.timeout_seconds)
    if a.provider == "anthropic":
        return ProviderConfig("anthropic", a.anthropic_model, secrets.get("anthropic_api_key"), timeout=a.timeout_seconds)
    if a.provider == "azure_openai":
        return ProviderConfig("azure_openai", a.azure_deployment, secrets.get("azure_openai_api_key"), a.azure_endpoint,
                              a.azure_api_version, a.timeout_seconds)
    if a.provider == "ollama":
        return ProviderConfig("ollama", a.ollama_model, None, a.ollama_url, timeout=a.timeout_seconds)
    return ProviderConfig("local", "deterministic", None)


def check_privacy(settings: Settings, cfg: ProviderConfig) -> None:
    if cfg.name == "local":
        return
    if cfg.name == "ollama" and is_local_url(cfg.endpoint):
        return
    if settings.privacy_mode:
        raise AIError("Mode Privacy Protection actif : aucune donnée n'est envoyée à un service distant. "
                      "Désactivez-le dans Paramètres pour utiliser ce fournisseur, ou utilisez le moteur local / Ollama local.")
    if cfg.name in ("openai", "anthropic", "azure_openai") and not cfg.api_key:
        raise AIError(f"Aucune clé API configurée pour {cfg.name} (Paramètres > Intelligence artificielle).")


# ------------------------------------------------------------------ moteur local déterministe

def local_analysis(result: dict) -> dict:
    from ..hunting.library import queries_for_rules

    findings = result.get("findings", [])
    active = [f for f in findings if f.get("status") not in ("False Positive",)]
    assessments = [{"statement": f"{f['title']} — {f['description']}", "status": f["status"],
                    "confidence": f["confidence"], "evidence_ids": f["evidence_ids"][:12], "mitre": f.get("mitre_ids", [])}
                   for f in active]
    hyps = []
    rules = {f["rule_id"] for f in active}
    if rules & {"R-PS-001", "R-OFF-001", "R-LOL-001"} and not rules & {"R-MAIL-001"}:
        hyps.append({"hypothesis": "Le vecteur initial pourrait être un e-mail ou un téléchargement web non présent dans les données.",
                     "how_to_validate": "Rechercher les e-mails reçus et les téléchargements de l'utilisateur dans l'heure "
                                        "précédant la première exécution suspecte.", "evidence_ids": []})
    if rules & {"R-CRD-001", "R-CRD-002"}:
        hyps.append({"hypothesis": "Des identifiants ont pu être réutilisés sur d'autres systèmes après leur extraction.",
                     "how_to_validate": "Rechercher les ouvertures de session réseau (type 3/10) des comptes présents sur "
                                        "l'hôte après l'heure de l'extraction.", "evidence_ids": []})
    if rules & {"R-NET-002", "R-NET-001", "R-DNS-001"}:
        hyps.append({"hypothesis": "D'autres hôtes communiquent avec la même infrastructure.",
                     "how_to_validate": "Rechercher les IOC réseau de l'investigation sur l'ensemble du parc (proxy, pare-feu, EDR).",
                     "evidence_ids": []})
    if not active:
        hyps.append({"hypothesis": "L'alerte d'origine pourrait refléter une activité légitime ou des données incomplètes.",
                     "how_to_validate": "Vérifier le contexte métier et collecter la télémétrie endpoint de l'hôte concerné.",
                     "evidence_ids": []})
    return {"executive_summary": result.get("summary", ""), "assessments": assessments, "rejected_assessments": [],
            "hypotheses": [h | {"label": "Hypothèse (non vérifiée)"} for h in hyps],
            "additional_queries": queries_for_rules(rules)[:8], "gaps": result.get("limitations", []),
            "analyst_questions": ["Les comptes et hôtes concernés sont-ils critiques pour l'activité ?",
                                  "Une intervention planifiée (déploiement, test, maintenance) peut-elle expliquer l'activité ?"]}


def run_ai_analysis(settings: Settings, secrets, result: dict, events: list, valid_techniques: set[str] | None = None,  # noqa: ANN001
                    transport: httpx.BaseTransport | None = None) -> dict:
    cfg = provider_config(settings, secrets)
    if cfg.name == "local":
        return {"provider": "local", "model": "moteur déterministe", **local_analysis(result)}
    check_privacy(settings, cfg)
    package = build_evidence_package(result, events, settings.ai.max_events_in_prompt)
    allowed = {e["id"] for e in package["events"]} | {f["finding_id"] for f in package["findings"]} | \
              {i for f in package["findings"] for i in (f.get("evidence_ids") or [])}
    user = ("Voici le paquet de preuves de l'investigation (JSON). Produis ton analyse selon le schéma imposé.\n"
            + json.dumps(package, ensure_ascii=False, default=str))
    raw = call_provider(cfg, SYSTEM_PROMPT, user, transport)
    validated = validate_ai_output(_extract_json(raw), allowed, valid_techniques)
    log.info("Analyse IA %s : %d affirmations retenues, %d rejetées", cfg.name, len(validated["assessments"]),
             len(validated["rejected_assessments"]))
    return {"provider": cfg.name, "model": cfg.model, **validated}


def test_connection(settings: Settings, secrets, transport: httpx.BaseTransport | None = None) -> str:  # noqa: ANN001
    cfg = provider_config(settings, secrets)
    if cfg.name == "local":
        return "Moteur local déterministe : disponible (aucune connexion requise)."
    check_privacy(settings, cfg)
    raw = call_provider(cfg, "Réponds uniquement avec le JSON {\"ok\": true}.", "Test de connexion.", transport)
    _extract_json(raw)
    return f"Connexion réussie à {cfg.name} (modèle {cfg.model})."
