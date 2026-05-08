import os
import yaml
from pathlib import Path

MITRE_PATH_DEFAULT = Path(__file__).parent / "mitre_attack_mapping.yml"
MITRE_PATH = Path(os.getenv("MITRE_MAPPING_PATH", str(MITRE_PATH_DEFAULT)))

def load_mitre_mapping():
    if not MITRE_PATH.exists():
        # Tenta fallback para o diretório atual se o path via env/default falhar e for relativo
        if not MITRE_PATH.is_absolute():
            alt_path = Path.cwd() / MITRE_PATH
            if alt_path.exists():
                return _load_from_path(alt_path)
        return {}, {}
    return _load_from_path(MITRE_PATH)

def _load_from_path(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            
            techniques = {t["id"]: t for t in data.get("techniques", [])}
            tactics = {t["id"]: t for t in data.get("tactics", [])}
            
            # Mapeamento reverso para facilitar busca por evento
            detection_mapping = data.get("detection_mapping", {})
            
            final_mapping = {}
            for event_type, mapping in detection_mapping.items():
                tech_id = mapping.get("technique_id")
                tech = techniques.get(tech_id, {})
                tactic_id = tech.get("tactic_id")
                tactic = tactics.get(tactic_id, {})
                
                final_mapping[event_type.upper()] = {
                    "id": tech_id,
                    "name": tech.get("name"),
                    "tactic": tactic.get("name"),
                    "kill_chain_stage": mapping.get("kill_chain_stage")
                }
            
            return final_mapping, techniques
    except Exception:
        return {}, {}

MITRE_MAPPING, MITRE_TECHNIQUES = load_mitre_mapping()

def get_mitre_mapping(event_type):
    event_type = str(event_type).upper()
    return MITRE_MAPPING.get(event_type, {"id": None, "name": "Unknown", "tactic": "Unknown"})

def get_technique_details(tech_id):
    return MITRE_TECHNIQUES.get(tech_id)
