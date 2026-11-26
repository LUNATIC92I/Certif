"""Threat Intelligence Engine : réputation des IOC (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox).

Principes :
- aucune requête n'est émise si le mode Privacy Protection est actif ou si aucun fournisseur n'est configuré ;
- seuls des indicateurs publics sont transmis (hash, IP publique, domaine/URL non internes) : jamais de noms
  d'utilisateurs, de chemins, de noms d'hôtes internes ni de contenu de journaux ;
- quotas respectés (intervalle minimal par fournisseur, gestion des réponses 429 et du Retry-After), délais d'attente,
  réponses invalides gérées ; résultats mis en cache et historisés.
"""
from __future__ import annotations

import base64
import json
import re
import threading
import time
from dataclasses import asdict, dataclass
from datetime import timedelta

import httpx
from sqlalchemy import select

from ..analysis.ioc import classify_ip
from ..core.logging_setup import get_logger
from ..db.models import TISearch, utcnow

log = get_logger("ti")

SUPPORTED = {  # fournisseur -> types d'IOC pris en charge
    "virustotal": {"sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url"},
    "abuseipdb": {"ipv4", "ipv6"},
    "otx": {"sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url"},
    "urlhaus": {"url", "domain", "ipv4", "sha256", "md5"},
    "malwarebazaar": {"sha256", "sha1", "md5"},
    "threatfox": {"sha256", "md5", "ipv4", "domain", "url"},
}
MIN_INTERVAL = {"virustotal": 15.5, "abuseipdb": 1.0, "otx": 0.5, "urlhaus": 1.0, "malwarebazaar": 1.0, "threatfox": 1.0}
SECRET_NAMES = {"virustotal": "virustotal_api_key", "abuseipdb": "abuseipdb_api_key", "otx": "otx_api_key",
                "urlhaus": "abusech_auth_key", "malwarebazaar": "abusech_auth_key", "threatfox": "abusech_auth_key"}
INTERNAL_DOMAIN = re.compile(r"(?i)\.(local|lan|corp|internal|intra|home|localdomain|ad)$")
VERDICT_RANK = {"Malveillant": 3, "Suspect": 2, "Aucune détection": 1, "Inconnu": 0, "Erreur": -1, "Non vérifié": -2}


@dataclass
class TIResult:
    provider: str
    indicator: str
    ioc_type: str
    status: str  # ok / not_found / error / skipped / rate_limited
    verdict: str
    summary: str
    raw: dict
    from_cache: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def detect_type(value: str) -> str:
    v = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "md5"
    if re.match(r"(?i)^(https?|ftp)://", v):
        return "url"
    c = classify_ip(v)
    if c:
        return c[0]
    if re.fullmatch(r"(?i)([a-z0-9-]+\.)+[a-z]{2,24}", v):
        return "domain"
    return "unknown"


def shareable(value: str, ioc_type: str) -> tuple[bool, str]:
    if ioc_type in ("sha256", "sha1", "md5"):
        return True, ""
    if ioc_type in ("ipv4", "ipv6"):
        scope = classify_ip(value)
        if not scope or scope[1] != "publique":
            return False, f"adresse {scope[1] if scope else 'invalide'} : non transmise"
        return True, ""
    if ioc_type == "domain":
        return (False, "domaine interne : non transmis") if INTERNAL_DOMAIN.search(value) else (True, "")
    if ioc_type == "url":
        host = re.sub(r"^[a-z]+://", "", value, flags=re.I).split("/")[0].split(":")[0]
        if INTERNAL_DOMAIN.search(host) or (classify_ip(host) and classify_ip(host)[1] != "publique"):
            return False, "URL interne : non transmise"
        return True, ""
    return False, "type non pris en charge par les services de réputation"


class TIEngine:
    def __init__(self, ctx, transport: httpx.BaseTransport | None = None):  # noqa: ANN001
        self.ctx = ctx
        self.transport = transport
        self._last_call: dict[str, float] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- configuration
    def configured(self) -> list[str]:
        en = self.ctx.settings.ti.enabled
        return [p for p in SUPPORTED if en.get(p) and self.ctx.secrets.has(SECRET_NAMES[p])]

    def status_text(self) -> str:
        if self.ctx.settings.privacy_mode:
            return "Mode Privacy Protection actif : aucune vérification de réputation externe (réputation non vérifiée)."
        conf = self.configured()
        if not conf:
            return "Aucun fournisseur de threat intelligence configuré : réputation non vérifiée."
        return "Fournisseurs actifs : " + ", ".join(conf)

    # ---------------------------------------------------------------- recherche
    def lookup(self, value: str, ioc_type: str | None = None, investigation_id: int | None = None,
               providers: list[str] | None = None) -> list[TIResult]:
        value = value.strip()
        ioc_type = ioc_type or detect_type(value)
        if self.ctx.settings.privacy_mode:
            return [TIResult("—", value, ioc_type, "skipped", "Non vérifié",
                             "Mode Privacy Protection actif : aucune donnée transmise.", {})]
        ok, why = shareable(value, ioc_type)
        if not ok:
            return [TIResult("—", value, ioc_type, "skipped", "Non vérifié", why.capitalize() + ".", {})]
        targets = [p for p in (providers or self.configured()) if p in self.configured() and ioc_type in SUPPORTED[p]]
        if not targets:
            return [TIResult("—", value, ioc_type, "skipped", "Non vérifié",
                             "Aucun fournisseur configuré ne prend en charge ce type d'indicateur : réputation non vérifiée.", {})]
        results = []
        for p in targets:
            cached = self._cached(p, value)
            if cached:
                results.append(cached)
                continue
            res = self._query(p, value, ioc_type)
            self._store(res, investigation_id)
            results.append(res)
        return results

    def _cached(self, provider: str, value: str) -> TIResult | None:
        hours = self.ctx.settings.ti.cache_hours
        if hours <= 0:
            return None
        since = utcnow() - timedelta(hours=hours)
        with self.ctx.db.session() as s:
            row = s.scalars(select(TISearch).where(TISearch.provider == provider, TISearch.indicator == value,
                                                   TISearch.status.in_(("ok", "not_found")), TISearch.created_at >= since)
                            .order_by(TISearch.created_at.desc())).first()
            if row:
                return TIResult(provider, value, row.ioc_type, row.status, row.verdict, row.summary,
                                json.loads(row.raw_json or "{}"), True)
        return None

    def _store(self, r: TIResult, investigation_id: int | None) -> None:
        with self.ctx.db.session() as s:
            s.add(TISearch(provider=r.provider, indicator=r.indicator[:2000], ioc_type=r.ioc_type, status=r.status,
                           verdict=r.verdict, summary=r.summary[:2000], raw_json=json.dumps(r.raw)[:200000],
                           investigation_id=investigation_id, from_cache=False))

    def _throttle(self, provider: str) -> None:
        with self._lock:
            wait = MIN_INTERVAL[provider] - (time.monotonic() - self._last_call.get(provider, 0.0))
            if wait > 0:
                time.sleep(wait)
            self._last_call[provider] = time.monotonic()

    def _query(self, provider: str, value: str, ioc_type: str) -> TIResult:
        key = self.ctx.secrets.get(SECRET_NAMES[provider]) or ""
        self._throttle(provider)
        timeout = httpx.Timeout(self.ctx.settings.ti.timeout_seconds, connect=10.0)
        try:
            with httpx.Client(timeout=timeout, transport=self.transport, headers={"User-Agent": "AI-SOC-ANALYST/1.0"}) as c:
                return getattr(self, f"_q_{provider}")(c, key, value, ioc_type)
        except httpx.TimeoutException:
            return TIResult(provider, value, ioc_type, "error", "Erreur", "Délai d'attente dépassé.", {})
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 429:
                retry = exc.response.headers.get("Retry-After", "?")
                return TIResult(provider, value, ioc_type, "rate_limited", "Erreur",
                                f"Quota atteint (HTTP 429), réessayer après {retry} s.", {})
            if code == 404:
                return TIResult(provider, value, ioc_type, "not_found", "Inconnu", "Indicateur inconnu du service.", {})
            msg = {401: "clé API invalide", 403: "accès refusé"}.get(code, "erreur du service")
            return TIResult(provider, value, ioc_type, "error", "Erreur", f"HTTP {code} ({msg}).", {})
        except httpx.HTTPError as exc:
            return TIResult(provider, value, ioc_type, "error", "Erreur", f"Erreur réseau : {type(exc).__name__}.", {})
        except (ValueError, KeyError, TypeError) as exc:
            return TIResult(provider, value, ioc_type, "error", "Erreur", f"Réponse invalide : {exc}", {})

    # ---------------------------------------------------------------- fournisseurs
    def _q_virustotal(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        path = {"sha256": "files", "sha1": "files", "md5": "files", "ipv4": "ip_addresses", "ipv6": "ip_addresses",
                "domain": "domains"}.get(t)
        ident = value if t != "url" else base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        r = c.get(f"https://www.virustotal.com/api/v3/{path or 'urls'}/{ident}", headers={"x-apikey": key})
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0
        verdict = "Malveillant" if mal >= 3 else "Suspect" if mal + sus >= 1 else "Aucune détection"
        names = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        summary = f"VirusTotal : {mal} détection(s) malveillante(s), {sus} suspecte(s) sur {total} moteurs" + \
                  (f" ; libellé : {names}" if names else "")
        return TIResult("virustotal", value, t, "ok", verdict, summary, {"stats": stats, "label": names})

    def _q_abuseipdb(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        r = c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": value, "maxAgeInDays": 90},
                  headers={"Key": key, "Accept": "application/json"})
        r.raise_for_status()
        d = r.json()["data"]
        score = int(d.get("abuseConfidenceScore", 0))
        verdict = "Malveillant" if score >= 75 else "Suspect" if score >= 25 else "Aucune détection"
        return TIResult("abuseipdb", value, t, "ok", verdict,
                        f"AbuseIPDB : score de confiance d'abus {score}/100, {d.get('totalReports', 0)} signalement(s), "
                        f"pays {d.get('countryCode') or '?'}, FAI {d.get('isp') or '?'}", d)

    def _q_otx(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        section = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url"}.get(t, "file")
        r = c.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general", headers={"X-OTX-API-KEY": key})
        r.raise_for_status()
        d = r.json()
        pulses = int(d.get("pulse_info", {}).get("count", 0))
        verdict = "Suspect" if pulses > 0 else "Aucune détection"
        return TIResult("otx", value, t, "ok", verdict, f"AlienVault OTX : référencé dans {pulses} pulse(s)",
                        {"pulse_count": pulses})

    def _abusech(self, c: httpx.Client, key: str, url: str, **kw) -> dict:
        r = c.post(url, headers={"Auth-Key": key}, **kw)
        r.raise_for_status()
        return r.json()

    def _q_urlhaus(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        if t == "url":
            d = self._abusech(c, key, "https://urlhaus-api.abuse.ch/v1/url/", data={"url": value})
        elif t in ("domain", "ipv4"):
            d = self._abusech(c, key, "https://urlhaus-api.abuse.ch/v1/host/", data={"host": value})
        else:
            d = self._abusech(c, key, "https://urlhaus-api.abuse.ch/v1/payload/",
                              data={"sha256_hash" if t == "sha256" else "md5_hash": value})
        if d.get("query_status") == "ok":
            threat = d.get("threat") or d.get("signature") or ", ".join(
                sorted({u.get("threat", "") for u in d.get("urls", [])[:20] if u.get("threat")}))
            return TIResult("urlhaus", value, t, "ok", "Malveillant", f"URLhaus : référencé ({threat or 'distribution de malware'})",
                            {k: d.get(k) for k in ("query_status", "threat", "url_status", "signature", "tags")})
        return TIResult("urlhaus", value, t, "not_found", "Inconnu", "URLhaus : non référencé", {"query_status": d.get("query_status")})

    def _q_malwarebazaar(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        d = self._abusech(c, key, "https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value})
        if d.get("query_status") == "ok" and d.get("data"):
            item = d["data"][0]
            return TIResult("malwarebazaar", value, t, "ok", "Malveillant",
                            f"MalwareBazaar : échantillon connu ({item.get('signature') or 'signature inconnue'}, "
                            f"type {item.get('file_type')})", {k: item.get(k) for k in ("signature", "file_type", "tags", "first_seen")})
        return TIResult("malwarebazaar", value, t, "not_found", "Inconnu", "MalwareBazaar : hash inconnu",
                        {"query_status": d.get("query_status")})

    def _q_threatfox(self, c: httpx.Client, key: str, value: str, t: str) -> TIResult:
        if t in ("sha256", "md5"):
            payload = {"query": "search_hash", "hash": value}
        else:
            payload = {"query": "search_ioc", "search_term": value}
        d = self._abusech(c, key, "https://threatfox-api.abuse.ch/api/v1/", json=payload)
        if d.get("query_status") == "ok" and d.get("data"):
            item = d["data"][0]
            return TIResult("threatfox", value, t, "ok", "Malveillant",
                            f"ThreatFox : IOC référencé ({item.get('malware_printable') or '?'}, "
                            f"confiance {item.get('confidence_level', '?')}%)",
                            {k: item.get(k) for k in ("malware_printable", "threat_type", "confidence_level", "first_seen")})
        return TIResult("threatfox", value, t, "not_found", "Inconnu", "ThreatFox : non référencé",
                        {"query_status": d.get("query_status")})

    # ---------------------------------------------------------------- agrégation
    @staticmethod
    def aggregate(results: list[TIResult]) -> tuple[str, str, str | None]:
        """Renvoie (réputation, résumé, risque suggéré)."""
        effective = [r for r in results if r.status in ("ok", "not_found")]
        if not effective:
            why = results[0].summary if results else "aucun fournisseur"
            return "Non vérifiée", why, None
        best = max(effective, key=lambda r: VERDICT_RANK.get(r.verdict, 0))
        summary = " | ".join(r.summary for r in effective)
        risk = {"Malveillant": "High", "Suspect": "Medium"}.get(best.verdict)
        return best.verdict, summary, risk

    def history(self, limit: int = 500) -> list[TISearch]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(TISearch).order_by(TISearch.created_at.desc()).limit(limit)).all())
