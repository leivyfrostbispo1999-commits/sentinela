# Guia de Troubleshooting: Docker e WSL2

## 1. Erro de DNS: `lookup http.docker.internal ... i/o timeout`
Este erro ocorre quando aplicações (especialmente em Python) tentam utilizar variáveis de ambiente injetadas pelo Docker Desktop no Windows (como `HTTP_PROXY`).
**Solução (já implementada):**
Os healthchecks no `docker-compose.yml` foram ajustados para forçar `os.environ['NO_PROXY']='127.0.0.1'` e consultar diretamente `127.0.0.1`.

## 2. Lentidão no Banco de Dados
Se você notar I/O muito lento ou alto uso de CPU pelo PostgreSQL no Windows:
**Causa:** Os arquivos mapeados em volume bind (ex: `./data:/var/lib/postgresql/data`) cruzam o file system do Windows para o WSL2 (9P protocol), o que tem péssima performance.
**Solução:** Sempre rode o Docker e coloque a pasta do projeto *dentro* do file system do WSL2 (ex: `\\wsl$\Ubuntu\home\user\sentinela`). O Sentinela já utiliza volumes nomeados nativos do Docker (`sentinela-db-data`), mitigando o problema.

## 3. Falha de Permissão em Arquivos .sh / .ps1
Se rodar no Git Bash ou WSL:
```bash
chmod +x scripts/*.ps1
```

## 4. Ocupação Excessiva de Disco
Ao longo dos testes locais com Kafka e Banco de Dados, os volumes podem crescer.
**Solução Limpa:**
Execute `.\scripts\clean-rebuild.ps1` periodicamente se os dados não precisarem ser persistidos.
