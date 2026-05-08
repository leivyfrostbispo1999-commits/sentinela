# XDR Telemetry Documentation

O SENTINELA suporta telemetria de múltiplos domínios para visibilidade total (XDR).

## Fluxo de Dados
`Raw Telemetry` -> `Enrichment (GeoIP/ThreatIntel)` -> `Enriched XDR Telemetry` -> `Analytics (Flink/AI/Graph)`

## Tópicos Kafka
- `raw_logs`: Porta de entrada para logs crus.
- `enriched_logs`: Logs com contexto geográfico e de reputação.
- `security_alerts`: Alertas gerados pelos motores de detecção.

## Domínios Cobertos
- **Endpoint**: Processos, arquivos e kernel.
- **Network**: Conexões, fluxos e varreduras.
- **Cloud**: API calls, alterações de infraestrutura.
- **Identity**: Logins, trocas de senha e escalação.
