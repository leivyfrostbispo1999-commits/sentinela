import hashlib
import os
import re
import json
import socket
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ENABLE_IOC_ENRICHMENT = os.getenv("ENABLE_IOC_ENRICHMENT", "true").lower() == "true"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
THREAT_TIMEOUT = float(os.getenv("THREAT_TIMEOUT", "2.0"))

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

def virustotal_lookup(value):
    if not VIRUSTOTAL_API_KEY:
        return None
    kind = indicator_type(value)
    # VT usa endpoints diferentes para cada tipo
    endpoint_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
    if kind not in endpoint_map:
        return None
    
    indicator = normalize_indicator(value)
    if kind == "url":
        # VT exige hash base64 sem padding ou SHA256 para URLs, simplificando aqui para exemplo estrutural
        return None

    url = f"https://www.virustotal.com/api/v3/{endpoint_map[kind]}/{indicator}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=THREAT_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0:
                return {
                    "reputation_score": min(100, 50 + (malicious * 10)),
                    "category": "MALICIOUS_VT",
                    "description": f"VirusTotal identificou {malicious} engines reportando como malicioso",
                    "source": "virustotal"
                }
    except Exception:
        pass
    return None

def abuseipdb_lookup(ip):
    if not ABUSEIPDB_API_KEY or indicator_type(ip) != "ip":
        return None
    
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=THREAT_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if score >= 25:
                return {
                    "reputation_score": score,
                    "category": "SUSPICIOUS_IP_ABUSEIPDB",
                    "description": f"AbuseIPDB reportou score de abuso de {score}%",
                    "source": "abuseipdb"
                }
    except Exception:
        pass
    return None

def local_lookup(value):
    indicator = normalize_indicator(value)
    kind = indicator_type(indicator)
    
    if kind == "ip":
        match = IP_DB.get(indicator)
    elif kind == "domain":
        match = DOMAIN_DB.get(indicator)
    elif kind == "url":
        match = URL_DB.get(indicator)
        if not match:
            host = urlparse(indicator).hostname or ""
            match = DOMAIN_DB.get(host.lower())
    elif kind == "hash":
        match = HASH_DB.get(indicator)
    else:
        match = None

    if match:
        return {**match, "indicator": indicator, "indicator_type": kind, "source": "local_mock"}
    return None

def check_ioc(value):
    if not ENABLE_IOC_ENRICHMENT:
        return None
    
    # Ordem de prioridade: Local -> AbuseIPDB (IPs) -> VirusTotal
    result = local_lookup(value)
    if result: return result
    
    kind = indicator_type(value)
    if kind == "ip":
        result = abuseipdb_lookup(value)
        if result: return result
        
    return virustotal_lookup(value)

def check_ip(ip):
    return check_ioc(ip)
