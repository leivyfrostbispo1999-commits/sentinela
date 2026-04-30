import time

def safe_db_insert(cursor, query, data):
    """
    Tenta inserir no banco de dados até 3 vezes antes de desistir.
    """
    for i in range(3):
        try:
            cursor.execute(query, data)
            # Se chegar aqui, deu certo. O return encerra a função.
            print("✅ Inserção no banco realizada com sucesso!")
            return 
        except Exception as e:
            print(f"⚠️ Erro no Banco (Tentativa {i+1}/3):", e)
            if i < 2: # Se não for a última tentativa, espera 2 segundos
                time.sleep(2)
            else:
                print("❌ Falha crítica: Não foi possível salvar no banco após 3 tentativas.")
