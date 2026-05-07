import hashlib
import os
import re
from urllib.parse import urlparse


ENABLE_IOC_ENRICHMENT = os.getenv("ENABLE_IOC_ENRICHMENT", "true").lower() == "true"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

IP_DB = {
    "45.67.89.12": {"reputation_score": 95, "category": "BOTNET", "description": "IP associado a botnet ativa"},
    "185.220.101.44": {"reputation_score": 90, "category": "TOR_EXIT_NODE", "description": "No de saida TOR usado para anonimizacao ofensiva"},
    "91.219.236.15": {"reputation_score": 88, "category": "SCANNER", "description": "Scanner agressivo de portas e servicos expostos"},
    "103.27.202.66": {"reputation_score": 92, "category": "CREDENTIAL_STUFFING", "description": "Origem simulada de tentativas massivas de login"},
    "172.16.5.67": {"reputation_score": 97, "category": "MALWARE_C2", "description": "Servidor de comando e controle simulado"},
}

DOMAIN_DB = {
    "malware.example": {"reputation_score": 91, "category": "MALWARE_DOMAIN", "description": "Dominio local associado a entrega de malware"},
    "phishing.example": {"reputation_score": 88, "category": "PHISHING", "description": "Dominio local associado a phishing"},
}

URL_DB = {
    "http://malware.example/dropper.exe": {"reputation_score": 96, "category": "MALWARE_URL", "description": "URL local simulada de payload malicioso"},
    "https://phishing.example/login": {"reputation_score": 89, "category": "PHISHING_URL", "description": "URL local simulada de coleta de credenciais"},
}

HASH_DB = {
    "44d88612fea8a8f36de82e1278abb02f": {"reputation_score": 99, "category": "EICAR_TEST", "description": "Hash MD5 de arquivo de teste EICAR"},
    "275a021bbfb6489e54d471899f7db9d1": {"reputation_score": 94, "category": "MALWARE_HASH", "description": "Hash local simulado de malware"},
}


def normalize_indicator(value):
    return str(value or "").strip().lower()


def indicator_type(value):
    indicator = normalize_indicator(value)
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", indicator):
        return "hash"
    if indicator.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", indicator):
        return "ip"
    if "." in indicator and " " not in indicator:
        return "domain"
    return "unknown"


def provider_metadata():
    providers = ["local_mock"]
    if VIRUSTOTAL_API_KEY:
        providers.append("virustotal_configured")
    if ABUSEIPDB_API_KEY:
        providers.append("abuseipdb_configured")
    if OTX_API_KEY:
        providers.append("otx_configured")
    return providers


def local_lookup(value):
    indicator = normalize_indicator(value)
    kind = indicator_type(indicator)
    if kind == "url":
        match = URL_DB.get(indicator)
        if not match:
            host = urlparse(indicator).hostname or ""
            match = DOMAIN_DB.get(host.lower())
    elif kind == "domain":
        match = DOMAIN_DB.get(indicator)
    elif kind == "hash":
        match = HASH_DB.get(indicator)
    elif kind == "ip":
        match = IP_DB.get(indicator)
    else:
        match = None
    if not match:
        return None
    return {**match, "indicator": indicator, "indicator_type": kind, "source": "local_mock", "providers": provider_metadata()}


def heuristic_lookup(value):
    indicator = normalize_indicator(value)
    kind = indicator_type(indicator)
    if kind == "domain" and any(token in indicator for token in ("malware", "phishing", "c2")):
        return {"indicator": indicator, "indicator_type": kind, "reputation_score": 76, "category": "SUSPICIOUS_DOMAIN", "description": "Heuristica local identificou dominio suspeito", "source": "heuristic_mock", "providers": provider_metadata()}
    if kind == "url" and any(token in indicator for token in ("login", "dropper", "payload", "cmd")):
        return {"indicator": indicator, "indicator_type": kind, "reputation_score": 78, "category": "SUSPICIOUS_URL", "description": "Heuristica local identificou URL suspeita", "source": "heuristic_mock", "providers": provider_metadata()}
    if kind == "hash":
        score = 70 + int(hashlib.sha256(indicator.encode("utf-8")).hexdigest()[:2], 16) % 20
        return {"indicator": indicator, "indicator_type": kind, "reputation_score": score, "category": "UNKNOWN_HASH", "description": "Hash desconhecido avaliado por mock local", "source": "heuristic_mock", "providers": provider_metadata()}
    return None


def check_ioc(value):
    if not ENABLE_IOC_ENRICHMENT:
        return None
    return local_lookup(value) or heuristic_lookup(value)


def check_ip(ip):
    result = check_ioc(ip)
    if result and result.get("indicator_type") == "ip":
        return result
    return None
