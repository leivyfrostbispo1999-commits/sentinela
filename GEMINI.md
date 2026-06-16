### Diretrizes de Idioma e Localização (pt-BR)
Toda a interface, documentação e mensagens operacionais do SENTINELA devem ser prioritariamente em português brasileiro (pt-BR).

**Padrões de Tradução:**
- **Interface e UX:** Títulos, descrições, botões, alertas e dashboards devem ser em pt-BR.
- **Relatórios e Logs:** Mensagens de erro, logs visuais e relatórios devem soar como um produto SaaS enterprise brasileiro.
- **Termos Técnicos Preservados:** Mantenha em inglês apenas termos consolidados (SOC, XDR, SIEM, MITRE ATT&CK, Playbook, Threat Intel, IOC, Brute Force, Port Scan, Docker, Kubernetes, API, Tenant, Score, Cluster, Deploy, Health Check, Webhook, Endpoint, Machine Learning, AI, Log, Cache, Pipeline, Firewall, Zero Trust, Token, JWT).
- **Evite Misturas:** Não utilize frases híbridas (inglês/português) desnecessariamente.
- **Naturalidade:** Prefira equivalentes naturais (Ex: "Inteligência de Caminho de Ataque" em vez de "Attack Path Intelligence").
- **Comentários de Código:** Podem permanecer em inglês.

### Protocolo de Coordenação entre Agentes
Antes de editar qualquer arquivo:
1. Leia `AGENTS_WORKLOG.md`.
2. Veja quais arquivos o outro agente está alterando.
3. Não edite arquivos marcados como "em uso".
4. Registre sua tarefa, arquivos pretendidos e horário no `AGENTS_WORKLOG.md`.
5. Ao terminar, atualize o status, testes executados e arquivos alterados no `AGENTS_WORKLOG.md`.
6. Antes de finalizar, rode `git status`.
