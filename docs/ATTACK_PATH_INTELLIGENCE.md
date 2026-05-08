# Attack Path Intelligence Documentation

O SENTINELA utiliza o Threat Graph para inferir trajetórias de ataque complexas.

## Algoritmo de Path Scoring
O score de um caminho de ataque (0-100) é calculado com base em:
1. **Severidade dos Alertas**: Alertas críticos aumentam o score.
2. **Criticidade dos Ativos**: Ativos marcados como `critical` elevam o risco do caminho.
3. **Reputação de IP**: IPs com alto `abuse_score` iniciam caminhos mais perigosos.
4. **Distância no Grafo**: Quanto mais entidades tocadas, maior o impacto potencial.

## Exemplo de Caminho Detectado
`(IP: Malicioso) -> (User: Compromised) -> (Host: JumpServer) -> (Process: sudo) -> (Cloud: AWS Deletion)`

## Endpoints
- `GET /attack-paths`: Lista caminhos ativos.
- `POST /attack-paths/recompute`: Força a análise do grafo para novos caminhos.
