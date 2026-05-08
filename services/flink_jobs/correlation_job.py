import os
import json
from pyflink.common import WatermarkStrategy, Encoder, Types
from pyflink.datastream import StreamExecutionEnvironment, RuntimeExecutionMode
from pyflink.datastream.connectors.kafka import KafkaSource, KafkaSink, KafkaRecordSerializationSchema
from pyflink.datastream.formats.json import JsonRowDeserializationSchema, JsonRowSerializationSchema
from pyflink.datastream.window import SlidingProcessingTimeWindows, Time
from pyflink.datastream.functions import KeyedProcessFunction, RuntimeContext

# Configurações via Ambiente
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = "enriched_logs"
OUTPUT_TOPIC = "security_alerts"

class AdvancedAttackCorrelation(KeyedProcessFunction):
    """
    Função de processamento de estado para detectar padrões multiestágio (Kill Chain).
    Padrão: PORT_SCAN -> FAILED_LOGIN -> SUCCESS (Lateral Movement / Breach)
    """
    def open(self, runtime_context: RuntimeContext):
        # Estados para rastrear a progressão do ataque por IP/Entidade
        self.stages_seen = runtime_context.get_state(Types.PICKLED_BYTE_ARRAY())
        self.last_timestamp = runtime_context.get_state(Types.LONG())

    def process_element(self, value, ctx: KeyedProcessFunction.Context):
        ip, event_type, score, ts, tenant = value
        
        stages = self.stages_seen.value() or []
        stages.append(event_type)
        
        # Limita histórico de estados por janela temporal simulada
        if len(stages) > 10: stages.pop(0)
        self.stages_seen.update(stages)

        # Lógica de Correlação de Sequências (Attack Chain Probability)
        # 1. Recon -> Access Attempt (Alta Probabilidade de Bruteforce direcionado)
        if "PORT_SCAN" in stages and any(ev in ["FAILED_LOGIN", "AUTH_FAILED"] for ev in stages):
            if event_type in ["FAILED_LOGIN", "AUTH_FAILED"]:
                confidence = 0.85
                yield self._create_alert(ip, "HIGH_CONFIDENCE_CHAIN_ATTEMPT", "HIGH", int(confidence*100), 
                                        f"Cadeia detectada: Reconhecimento seguido de tentativa de acesso ({confidence*100}% conf).", tenant, ts)

        # 2. Access -> Privilege Escalation (Indicação de Post-Exploitation)
        if any(ev in ["SUCCESSFUL_LOGIN", "LOGIN"] for ev in stages) and "ENDPOINT_PROCESS_START" in stages:
            if "sudo" in str(log.get("command_line", "")).lower() or "whoami" in str(log.get("command_line", "")).lower():
                yield self._create_alert(ip, "POST_EXPLOTATION_SEQUENCE", "CRITICAL", 95, 
                                        "Sequência Crítica: Login seguido de execução de comandos de auditoria/privilégio.", tenant, ts)

        # 4. Privilege Escalation -> Cloud Abuse (Padrão de Brecha na Nuvem)
        if "PRIVILEGE_ESCALATION" in stages and ("CLOUD_API_CALL" in stages or "CLOUD_API_ABUSE" in stages):
            if "Delete" in str(log.get("api_call", "")):
                yield self._create_alert(ip, "CLOUD_DESTRUCTION_AFTER_ESCALATION", "CRITICAL", 99, 
                                        "ALERTA CRÍTICO: Escalação de privilégio seguida de destruição de recursos cloud.", tenant, ts)

        # 5. Multi-Host lateral chain (Invasão propagada)
        involved_hosts = set(e.get("target_host") for e in history if e.get("target_host"))
        if len(involved_hosts) > 3:
            yield self._create_alert(ip, "WIDE_LATERAL_MOVEMENT_CAMPAIGN", "CRITICAL", 90,
                                    f"Campanha detectada: IPs externos tocando {len(involved_hosts)} hosts internos distintos.", tenant, ts)

    def _create_alert(self, ip, type, severity, risk, explanation, tenant, ts):
        alert = {
            "event_id": f"flink-cep-{ip}-{uuid_short()}",
            "source_ip": ip,
            "event_type": type,
            "severity": severity,
            "risco": risk,
            "explanation": f"FLINK CEP: {explanation}",
            "tenant_id": tenant,
            "ts": ts,
            "detection_source": "flink_cep_engine"
        }
        return json.dumps(alert)

def uuid_short():
    import uuid
    return uuid.uuid4().hex[:6]

def run_correlation_job():
    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_runtime_mode(RuntimeExecutionMode.STREAMING)
    
    source = KafkaSource.builder() \
        .set_bootstrap_servers(KAFKA_BOOTSTRAP_SERVERS) \
        .set_topics(INPUT_TOPIC) \
        .set_group_id("flink-advanced-cep-v1") \
        .set_value_only_deserializer(JsonRowDeserializationSchema.builder() \
            .type_info(Types.ROW_NAMED(
                ["source_ip", "event_type", "threat_score", "ts", "tenant_id"],
                [Types.STRING(), Types.STRING(), Types.INT(), Types.STRING(), Types.STRING()]
            )).build()) \
        .build()

    ds = env.from_source(source, WatermarkStrategy.no_watermarks(), "Enriched Source")

    # Aplica a correlação avançada com estado (Stateful Stream Processing)
    alert_stream = ds.key_by(lambda row: row[0]) \
        .process(AdvancedAttackCorrelation())

    sink = KafkaSink.builder() \
        .set_bootstrap_servers(KAFKA_BOOTSTRAP_SERVERS) \
        .set_record_serializer(KafkaRecordSerializationSchema.builder() \
            .set_topic(OUTPUT_TOPIC) \
            .set_value_serialization_schema(JsonRowSerializationSchema.builder() \
                .with_type_info(Types.STRING()).build()) \
            .build()) \
        .build()

    alert_stream.sink_to(sink)
    env.execute("Sentinela Advanced CEP")

if __name__ == "__main__":
    run_correlation_job()
