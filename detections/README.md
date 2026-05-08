# Detection Engineering no SENTINELA

As regras de detecção são armazenadas em arquivos YAML dentro deste diretório.

## Estrutura de uma Regra:
- **name**: Nome único da regra.
- **description**: Descrição do que a regra detecta.
- **enabled**: Booleano para ativar/desativar.
- **event_type**: Tipo de evento (ex: FAILED_LOGIN, PORT_SCAN).
- **threshold**: Número de ocorrências para disparar.
- **window_seconds**: Janela temporal em segundos.
- **score**: Risco associado (0-100).
- **severity**: LOW, MEDIUM, HIGH, CRITICAL.
- **mitre_id**: ID da técnica MITRE ATT&CK.
- **action**: monitor, simulated_block.

## Como adicionar novas regras:
Basta criar um novo arquivo `.yml` neste diretório ou adicionar à `default_rules.yml`. O `rule_engine` irá carregar as regras conforme configurado em `RULES_PATH`.
