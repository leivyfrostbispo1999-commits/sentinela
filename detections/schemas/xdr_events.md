# XDR Telemetry Schemas

O SENTINELA ingere telemetria cross-domain padronizada para permitir correlação avançada.

## 1. Endpoint Telemetry (Process)
- `event_type`: `ENDPOINT_PROCESS_START`
- `process_name`: Nome do executável.
- `pid`: Process ID.
- `parent_pid`: PID do processo pai.
- `command_line`: Linha de comando completa.
- `target_host`: Host onde o processo iniciou.

## 2. Network Telemetry
- `event_type`: `NETWORK_CONNECTION`
- `source_ip`: IP de origem.
- `destination_ip`: IP de destino.
- `port`: Porta de destino.
- `protocol`: TCP/UDP.

## 3. Cloud Telemetry (AWS Example)
- `event_type`: `CLOUD_API_CALL`
- `cloud_provider`: `AWS`
- `api_call`: Nome da função (ex: `AssumeRole`).
- `cloud_account`: ID da conta.
- `user_agent`: Agente que realizou a chamada.

## 4. Identity Telemetry
- `event_type`: `AUTHENTICATION_EVENT`
- `username`: Usuário envolvido.
- `status`: `SUCCESS` / `FAILURE`.
- `source_ip`: IP de origem da tentativa.
