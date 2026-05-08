# Validação de Runtime do Sentinela

Este documento detalha como validar se a infraestrutura e os serviços do Sentinela estão rodando corretamente após um deploy ou rebuild.

## 1. Subindo o Ambiente

Se você precisa de um ambiente completamente limpo, execute no PowerShell:
```powershell
.\scripts\clean-rebuild.ps1
```

Caso queira apenas subir o ambiente existente:
```powershell
docker compose up -d
```

## 2. Validação Automática

O projeto possui um script PowerShell que checa todos os healthchecks e endpoints críticos:
```powershell
.\scripts\validate-runtime.ps1
```

## 3. Validação Manual de Serviços e Banco de Dados

### 3.1. Verificar Status dos Containers
```powershell
docker compose ps
```
Verifique se a coluna "STATUS" de todos os serviços principais mostra `(healthy)`.

### 3.2. Acesso à API do Dashboard
```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```

### 3.3. PostgreSQL
Verifique se o banco aceita conexões:
```powershell
docker compose exec db pg_isready -U postgres -d postgres
```

### 3.4. Kafka e DLQ (Dead Letter Queue)
Verifique se os tópicos foram criados corretamente (o Kafka auto-cria tópicos se `KAFKA_AUTO_CREATE_TOPICS_ENABLE="true"`).
```powershell
docker compose exec kafka kafka-topics --bootstrap-server 127.0.0.1:9092 --list
```
*Tópicos esperados:* `raw_logs`, `security_alerts`, `dead_letter_events`.

## 4. Retries e Tolerância a Falhas

Os serviços baseados em Kafka (Rule Engine, Alert Sink) utilizam política de retry exponencial.
Para validar se o retries está funcionando e mensagens falhas estão caindo na DLQ (`dead_letter_events`):
```powershell
docker compose exec kafka kafka-console-consumer --bootstrap-server 127.0.0.1:9092 --topic dead_letter_events --from-beginning --max-messages 10
```

## 5. Geração de Eventos e Tráfego

Para injetar tráfego no pipeline e observar os serviços operando:
```powershell
python scripts/replay_attack.py --count 100
```
Isso publicará eventos de ataque no tópico `raw_logs`, que serão processados pela Rule Engine.
