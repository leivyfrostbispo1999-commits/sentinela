THREAT_DB = {
    "45.67.89.12": {
        "reputation_score": 95,
        "category": "BOTNET",
        "description": "IP associado a botnet ativa",
    },
    "185.220.101.44": {
        "reputation_score": 90,
        "category": "TOR_EXIT_NODE",
        "description": "Nó de saída TOR usado para anonimização ofensiva",
    },
    "91.219.236.15": {
        "reputation_score": 88,
        "category": "SCANNER",
        "description": "Scanner agressivo de portas e serviços expostos",
    },
    "103.27.202.66": {
        "reputation_score": 92,
        "category": "CREDENTIAL_STUFFING",
        "description": "Origem simulada de tentativas massivas de login",
    },
    "172.16.5.67": {
        "reputation_score": 97,
        "category": "MALWARE_C2",
        "description": "Servidor de comando e controle simulado",
    },
}


def check_ip(ip):
    return THREAT_DB.get(str(ip), None)
