# Threat Graph Data Model

O SENTINELA utiliza Neo4j para modelar o ecossistema de segurança como um grafo de conhecimento.

## Entidades (Nodes)
- **Tenant**: Agrupador lógico de clientes SaaS.
- **IP**: Endereço de rede (enriquecido com país e risk score).
- **Host**: Ativos computacionais (servidores, workstations).
- **User**: Identidades (usuários reais ou de serviço).
- **Process**: Execução de binários em hosts (rastreia PID e linha de comando).
- **CloudAccount**: Contas de provedores de nuvem (AWS/Azure).
- **Alert**: Detecções unitárias geradas pelos motores.
- **Campaign**: Agrupamento de alertas correlacionados no tempo e espaço.

## Relacionamentos (Edges)
- `(IP)-[:BELONGS_TO]->(Tenant)`
- `(IP)-[:LOGGED_IN_FROM {status}]->(User)`
- `(User)-[:AUTHENTICATED_TO]->(Host)`
- `(Host)-[:TOUCHED_ASSET]->(Process)`
- `(Process)-[:SPAWNED_PROCESS]->(Process)`
- `(IP)-[:CALLED_API]->(CloudAccount)`
- `(IP)-[:CAUSED]->(Alert)`
- `(Alert)-[:PART_OF_CAMPAIGN]->(Campaign)`
- `(Alert)-[:GENERATED_ALERT]->(Tenant)`

## Vantagens
- **Attack Path Inference**: Identifica caminhos de movimento lateral.
- **Blast Radius**: Calcula o impacto total de uma conta ou IP comprometido.
- **Semantic Enrichment**: Ativos e identidades possuem scores de risco dinâmicos.
