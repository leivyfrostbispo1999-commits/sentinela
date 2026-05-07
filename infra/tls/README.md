# TLS local

Monte certificados reais ou self-signed neste diretório antes de subir o profile `production`.

Arquivos esperados por padrão:

- `infra/tls/certs/server.crt`
- `infra/tls/certs/server.key`

Exemplo com OpenSSL:

```bash
mkdir -p infra/tls/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout infra/tls/certs/server.key \
  -out infra/tls/certs/server.crt \
  -subj "/CN=localhost"
```
