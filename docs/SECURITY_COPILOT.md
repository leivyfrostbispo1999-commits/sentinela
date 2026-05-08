# Security Copilot Documentation

O SENTINELA integra uma plataforma de Copilot SOC para auxiliar analistas na triagem e resposta.

## Capacidades Generativas
1. **Summarize Incident**: Gera um parágrafo executivo explicando o incidente.
2. **Attack Hypothesis**: Infere a motivação e o método provável do atacante.
3. **Response Recommendation**: Sugere ações SOAR e investigações manuais.
4. **Hunting Query Generation**: Cria queries Cypher (Neo4j) e SQL baseadas no contexto.
5. **MITRE Analyst**: Explica as táticas e técnicas mapeadas no incidente.

## Integração LLM
O Copilot opera em dois modos:
- **Local (Deterministic)**: Utiliza mecanismos de template baseados em grafos e heurísticas para gerar insights sem custo.
- **AI (LLM Provider)**: Pode ser conectado a APIs (OpenAI/Anthropic) via abstração de provider no `dashboard_api`.

## Endpoints
- `POST /copilot/summarize-incident`
- `GET /copilot/incident/{id}`
