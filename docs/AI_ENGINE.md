# AI Engine Documentation

O SENTINELA utiliza aprendizado de máquina não supervisionado para detecção de anomalias XDR.

## Modelo: Isolation Forest
O motor de IA utiliza o algoritmo `Isolation Forest` (via `scikit-learn`) para identificar eventos que se desviam estatisticamente do comportamento normal de um tenant.

## Feature Engineering (7 Dimensões)
1. **Identity Score**: Frequência de falhas de autenticação.
2. **Process Spawn Rate**: Velocidade de criação de novos processos no endpoint.
3. **Suspicious Command Score**: Presença de keywords perigosas (`mimikatz`, `sudo`, `curl`) em linhas de comando.
4. **Port Entropy**: Diversidade de portas acessadas por um IP.
5. **Host Entropy**: Diversidade de hosts internos tocados.
6. **Cloud Abuse Score**: Frequência de chamadas de API cloud destrutivas (Ex: `DeleteTrail`).
7. **Base Threat Score**: Reputação global do IP (via Threat Intel).

## Fluxo de Inferência
`Enriched Log` -> `Feature Extraction` -> `Isolation Forest Predict` -> `AI Alert Generation`
