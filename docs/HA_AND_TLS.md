# HA and TLS

## Health e readiness

- `GET /health`: processo vivo.
- `GET /ready`: dependência mínima PostgreSQL acessível.

```powershell
curl http://localhost:5000/health
curl http://localhost:5000/ready
```

## Profile production/TLS

Gerar ou montar certificados:

```bash
mkdir -p infra/tls/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout infra/tls/certs/server.key \
  -out infra/tls/certs/server.crt \
  -subj "/CN=localhost"
```

Subir:

```powershell
docker compose --profile production up -d --build
```

Acessos:

- HTTPS: https://localhost:8443
- HTTP proxy: http://localhost:8088

Variáveis:

```text
ENABLE_TLS=true
TLS_CERT_PATH=./infra/tls/certs/server.crt
TLS_KEY_PATH=./infra/tls/certs/server.key
TLS_HTTPS_PORT=8443
TLS_HTTP_PORT=8088
```

## Escala básica

```powershell
docker compose up -d --scale dashboard_api=2
```

Limitação conhecida: WebSocket em múltiplas réplicas precisa de fanout compartilhado para consistência total. Próximo passo recomendado: Redis pub/sub ou Kafka topic dedicado para broadcast realtime.
