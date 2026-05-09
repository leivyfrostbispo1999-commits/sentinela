# SENTINELA AI-native Security Operations Platform

O SENTINELA é uma plataforma avançada de detecção e resposta (XDR) potencializada por Inteligência Artificial, Grafos de Ameaça e Copilot SOC.

## 🚀 Capacidades Enterprise

- **AI-native XDR**: Ingestão e correlação de telemetria de Endpoint, Rede, Cloud e Identidade.
- **Threat Graph Platform**: Modelagem completa de ativos e ameaças em Neo4j (Attack Path Inference).
- **Autonomous SOC**: Resposta automática governada por humanos com playbooks de mitigação.
- **Security Copilot**: Assistente de IA Generativa para resumo de incidentes e hunting assistido.
- **Real ML Engine**: Detecção de anomalias via Isolation Forest (scikit-learn) em tempo real.
- **Flink CEP**: Complex Event Processing para detecção de sequências multiestágio da Kill Chain.

## 🛠️ Arquitetura Modular (Profiles)

O SENTINELA suporta execução segmentada para otimização de recursos locais.

```text
📦 SENTINELA PLATFORM
├── 🔹 CORE (Essencial)
│   ├── API & Dashboard
│   ├── Kafka & Redis
│   └── Rule Engine & Enrichment
├── 🔸 ANALYTICS (IA & Stream)
│   ├── Apache Flink
│   ├── AI Engine (ML Real)
│   └── UEBA Engine
├── 🟣 GRAPH (Intelligence)
│   ├── Neo4j Database
│   └── Graph Relationship Engine
└── 🔍 SEARCH (Storage)
    └── OpenSearch Cold Storage
```

### Como Iniciar por Módulo (UX Otimizada)

Utilize os scripts automatizados para subir apenas o que você precisa:

```powershell
# Sobe o essencial (Recomendado para uso diário)
./scripts/infra/start-sentinela.ps1 -Profile core

# Sobe o ambiente de IA e Stream Processing
./scripts/infra/start-sentinela.ps1 -Profile analytics

# Sobe o Grafo de Ameaças e XDR Path Analysis
./scripts/infra/start-sentinela.ps1 -Profile graph

# Sobe o "God Mode" completo (Atenção: Exige 12GB+ RAM)
./scripts/infra/start-sentinela.ps1 -Profile full
```

*Nota: Use o parâmetro `-Build` para forçar a reconstrução das imagens.*

### 🛠️ Recuperar Docker Desktop travado via terminal

Caso encontre o erro "Docker Desktop is unable to start", utilize o protocolo de auto-recuperação:

1. Abra o PowerShell como Administrador.
2. Permita a execução de scripts (se necessário):
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Execute o script de recuperação para o perfil desejado:
   ```powershell
   # Recupera e sobe o essencial (CORE)
   .\scripts\infra\recover-docker.ps1 -Profile core

   # Recupera e reconstrói a stack completa (FULL)
   .\scripts\infra\recover-docker.ps1 -Profile full -Rebuild
   ```

---

### 🔍 Troubleshooting: localhost:8080 ERR_CONNECTION_REFUSED

Se o Dashboard não carregar no navegador, siga este roteiro de diagnóstico:

1. **Verifique se o perfil CORE está ativo**:
   ```powershell
   ./scripts/infra/start-sentinela.ps1 -Profile core
   ```
2. **Execute o script de diagnóstico**:
   ```powershell
   ./scripts/infra/check-dashboard.ps1
   ```
3. **Reconstrua o frontend se necessário**:
   ```powershell
   docker compose --profile core up -d --build --force-recreate
   ```
4. **Analise os logs de erro**:
   ```powershell
   docker compose logs dashboard_web --tail=100
   docker compose logs dashboard_api --tail=100
   ```

---

## 🛠️ Tecnologias
- **Data**: Kafka, Apache Flink, Redis.
- **Storage**: PostgreSQL (Hot), OpenSearch (Cold), Neo4j (Graph).
- **AI/ML**: scikit-learn, LLM Abstraction.
- **Infra**: Docker, Kubernetes, Terraform.

## 📁 Documentação Avançada
- [Arquitetura AI-native](docs/ARCHITECTURE.md)
- [Guia Operacional](docs/OPERATING_GUIDE.md)
- [Threat Graph Model](docs/THREAT_GRAPH.md)
- [Attack Path Intelligence](docs/ATTACK_PATH_INTELLIGENCE.md)
- [Autonomous SOC & SOAR](docs/AUTONOMOUS_SOC.md)
- [Security Copilot](docs/SECURITY_COPILOT.md)
- [AI Engine & ML](docs/AI_ENGINE.md)

## 🛠️ Como Iniciar Localmente

### Pré-requisitos
- Docker & Docker Compose
- Python 3.11+ (para scripts locais)

### Subir o Ambiente
```bash
docker compose up --build -d
```

### Rodar Replay Ofensivo
```bash
python scripts/replay_attack.py --delay 0.5
```

### Executar Testes de Performance
```bash
python tools/performance/load_generator.py
```

### Visualizar Dashboard
Acesse: [http://localhost:5000](http://localhost:5000)

## 📁 Estrutura do Projeto
- `services/`: Microsserviços (Rule Engine, UEBA, Lifecycle, Dashboard API, etc.).
- `detections/`: Regras de detecção versionadas em YAML.
- `infra/`: Manifests K8s, Terraform AWS e configurações de DB/Nginx.
- `tools/`: Ferramentas de performance e utilitários.
- `scripts/`: Scripts de replay de ataque e manutenção.

## 🛡️ Segurança e Qualidade
- CI/CD integrado com Bandit (lint de segurança) e Trivy (escaneamento de vulnerabilidades).
- Testes unitários e de integração via Pytest.
- Auditoria completa de ações SOAR.

---
*Este projeto é para fins educacionais e de laboratório SOC.*
