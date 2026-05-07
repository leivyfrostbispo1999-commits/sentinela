# Token Rotation

`POST /auth/token` retorna:

```json
{
  "token": "<access_token legado>",
  "access_token": "<access_token>",
  "refresh_token": "<refresh_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 604800
}
```

`token` foi preservado para compatibilidade com clientes atuais.

## Refresh

```powershell
curl -X POST http://localhost:5000/auth/refresh `
  -H "Content-Type: application/json" `
  -d "{\"refresh_token\":\"<REFRESH_TOKEN>\"}"
```

Regras:

- access token não é aceito como refresh;
- refresh expirado falha;
- refresh inválido falha;
- refresh token não é logado.

Variáveis:

```text
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=10080
```
