import redis
import os
import time
import json

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_PREFIX = "sentinela:stream:"
CORRELATION_PREFIX = "sentinela:correlation:"
ALERT_PREFIX = "sentinela:rule_engine:alerts:"

def cleanup():
    print(f"Iniciando limpeza de memória Redis em {REDIS_URL}...")
    r = redis.from_url(REDIS_URL, decode_responses=True)
    
    # 1. Limpeza de Streams (XTRIM por ID de tempo)
    stream_keys = r.keys(f"{STREAM_PREFIX}*")
    print(f"Encontradas {len(stream_keys)} streams de ataque.")
    
    # Manter apenas eventos dos últimos 30 minutos (1800 segundos) nas streams
    now_ms = int(time.time() * 1000)
    trim_id = f"{now_ms - (1800 * 1000)}-0"
    
    for key in stream_keys:
        try:
            removed = r.xtrim(key, minid=trim_id, approximate=True)
            # Se a stream estiver vazia após o trim e não tiver novos eventos, o Redis eventualmente a removerá pelo TTL
            # Mas podemos forçar o TTL aqui também
            r.expire(key, 3600) 
        except Exception as e:
            print(f"Erro ao limpar stream {key}: {e}")

    # 2. Limpeza de chaves de correlação legadas sem TTL
    corr_keys = r.keys(f"{CORRELATION_PREFIX}*")
    print(f"Encontradas {len(corr_keys)} chaves de correlação.")
    for key in corr_keys:
        if r.ttl(key) == -1: # Sem TTL
            r.expire(key, 600) # Define 10 minutos para expirar

    # 3. Limpeza de agregados de alertas
    alert_keys = r.keys(f"{ALERT_PREFIX}*")
    print(f"Encontradas {len(alert_keys)} chaves de agregados de alertas.")
    for key in alert_keys:
        if r.ttl(key) == -1:
            r.expire(key, 300)

    print("Limpeza concluída com sucesso.")

if __name__ == "__main__":
    cleanup()
