# SENTINELA Oracle Ops

Operação do SENTINELA em Oracle Cloud Free Tier, com foco em produção micro estável, automação de recuperação, governança de segurança e preparação para Kubernetes enxuto com k3s.

## Acesso

Ambiente Oracle atual:

https://levi-sentinela.duckdns.org/

Este é o endereço público correto do dashboard. Endereços `localhost` neste repositório são apenas para execução local de desenvolvimento.

## Estado Operacional

Produção micro atual:

- Oracle VM `SENTINELA-AMD-TEST`
- Docker Compose enxuto
- Dashboard web
- Dashboard API
- PostgreSQL
- Redis
- Autenticação habilitada
- Refresh token
- Expiração de sessão
- Gestão de usuários
- Auditoria operacional
- Ciclo de vida de alertas
- Isolamento por tenant no backend

Preparado para próximo nível:

- k3s em Oracle Free Tier
- PostgreSQL e Redis persistentes
- NATS para fila leve
- Prometheus e Grafana enxutos
- Ingress com TLS
- RBAC e NetworkPolicy
- HPA e PodDisruptionBudget
- Overlays Kubernetes para `dev`, `prod`, `oracle-k3s` e `mtls-linkerd`
- CI/CD com validação e build de containers

Limitação atual:

- A conta Oracle está inscrita apenas em `sa-saopaulo-1`.
- Tentativas de criar `VM.Standard.A1.Flex` falharam com `Out of host capacity`.
- Tentativas de assinar `us-ashburn-1` e `us-phoenix-1` falharam com `TenantCapacityExceeded`.
- O cluster k3s está pronto no repositório, mas depende da Oracle liberar capacidade ARM.

## Execução Local

Pré-requisitos:

- Docker Desktop ou Docker Engine
- Docker Compose
- Python 3.11+

Subir o ambiente local:

```powershell
docker compose up -d --build
```

Abrir dashboard local:

```text
http://localhost:8080
```

Verificar serviços:

```powershell
docker compose ps
docker compose logs --tail=120
```

Executar testes:

```powershell
py -m pytest -q
```

## Oracle k3s

Runbook principal:

```text
ops/oci/RUNBOOK_K3S_ORACLE.md
```

Overlay Free Tier:

```text
infra/k8s/overlays/oracle-k3s
```

Scripts principais:

```text
ops/oci/k3s_server_install.sh
ops/oci/k3s_worker_join.sh
ops/oci/k3s_label_nodes.sh
ops/oci/k3s_install_addons.sh
ops/oci/k3s_deploy_sentinela.sh
```

Arquivos OCI auxiliares:

```text
ops/oci/sentinela-arm-source-50gb.json
ops/oci/sentinela-arm-shape-1x4.json
ops/oci/sentinela-security-ingress-k3s.json
```

## Estrutura

- `services/`: API, frontend, rule engine, enrichment, alert sink e demais serviços.
- `infra/db/`: schema e inicialização do PostgreSQL.
- `infra/k8s/`: manifests e overlays Kubernetes.
- `ops/`: scripts operacionais, recuperação, diagnóstico e OCI.
- `docs/`: documentação de arquitetura, segurança, observabilidade e evolução.
- `.github/workflows/`: CI e release de containers.

## Segurança

O repositório não deve armazenar segredos reais. Use variáveis de ambiente, secrets do GitHub Actions ou Kubernetes Secrets.

O overlay `oracle-k3s` não aplica `secret.example.yaml`; o deploy cria `sentinela-secrets` no cluster quando necessário e salva as credenciais iniciais no host em:

```text
~/.sentinela-k3s-credentials
```

## Validações Recentes

Validações executadas antes da publicação:

```text
83 passed
yaml-ok 35
```

## Roadmap Pragmático

1. Manter a produção micro estável na VM atual.
2. Continuar tentando ARM Ampere em `sa-saopaulo-1` quando houver capacidade.
3. Subir k3s single-node primeiro.
4. Expandir para multi-node somente quando a Oracle liberar mais VMs ARM.
5. Manter observabilidade leve para não exceder os limites do Free Tier.

## Licença e Uso

Projeto para laboratório SOC, estudo de segurança defensiva e evolução operacional cloud-native do SENTINELA.
