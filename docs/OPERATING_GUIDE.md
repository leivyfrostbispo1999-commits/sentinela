# Operating Guide: SENTINELA AI-native Platform

Este guia descreve como operar as funcionalidades avançadas do SENTINELA.

## 1. Monitoramento XDR
Utilize o painel **AI-Native XDR Analytics** para visualizar anomalias estatísticas detectadas pelo Isolation Forest. 
- Alertas com `ai_anomaly_score > 0.8` devem ser priorizados.

## 2. Investigação de Caminhos de Ataque
A seção **Attack Path Intelligence** mostra trajetórias cross-domain.
- Clique em um IP ou Host para ver o **Blast Radius** no grafo do Neo4j.
- Use queries Cypher recomendadas pelo Copilot para aprofundar a busca por movimento lateral.

## 3. Uso do Security Copilot
Dentro de qualquer incidente crítico, clique em **Invocar Copilot AI**.
- A IA analisará o grafo e os logs para sugerir o próximo passo investigativo.
- O Copilot sugere playbooks SOAR adequados.

## 4. Governança SOAR
Ações críticas (quarentena, suspensão de acesso) exigem aprovação.
- Vá para a seção **Ações SOAR Pendentes**.
- Revise a explicação da IA/Regra e clique em **Aprovar** ou **Rejeitar**.
