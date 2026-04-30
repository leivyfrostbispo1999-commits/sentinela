# 1. Primeiro você define a função (no topo do arquivo)
def send_to_dlq(producer, event):
    print(f"⚠️ Enviando para DLQ: {event}")
    producer.produce(
        "dlq", 
        value=str(event).encode('utf-8'),
        callback=lambda err, msg: print("✅ Confirmado na DLQ") if err is None else print(f"❌ Erro DLQ: {err}")
    )
    producer.flush()

# 2. Depois, dentro do seu loop principal ou função de processamento:
try:
    # Sua lógica de validar IP/Regras aqui
    process_event(event) # Exemplo: validar se o IP é suspeito
except Exception as e:
    # Se algo falhar, o fallback entra em ação
    send_to_dlq(producer, event)
