# Visão de Produto: SENTINELA SOC Platform

## Objetivo
O SENTINELA visa democratizar a visibilidade de segurança para pequenas e médias empresas e estudantes, oferecendo uma plataforma SOC (Security Operations Center) leve, cloud-native e altamente extensível.

## Personas
1. **Analista de SOC Junior**: Busca uma interface intuitiva para triagem de alertas e investigação de campanhas.
2. **Engenheiro de Detecção**: Precisa de um ambiente para testar regras (YAML) e simular ataques (Replay).
3. **Estudante de Cibersegurança**: Utiliza o laboratório local para entender o Cyber Kill Chain e táticas MITRE ATT&CK.

## Diferenciais
- **Low-Cost**: Arquitetura otimizada para rodar em hardware modesto ou instâncias cloud pequenas.
- **Open Standards**: Uso massivo de MITRE ATT&CK e regras inspiradas no padrão Sigma.
- **Resiliência Integrada**: Pipeline com Kafka e monitoramento via Prometheus/Grafana.

## Roadmap 2026
- **Q3**: Integração nativa com OpenSearch para Long-Term Retention.
- **Q4**: Engine de correlação baseada em Grafos (Neo4j).
- **Q1 2027**: App Mobile para notificações críticas e aprovação de ações SOAR via push.

## Limitações Atuais
- Interface web puramente estática (necessita evolução para React/Angular em escala).
- Detecção baseada apenas em logs (falta ingestão de rede via PCAP).
