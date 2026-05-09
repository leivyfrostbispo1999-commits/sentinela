import os
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4317")
SERVICE_NAME_VAL = os.getenv("OTEL_SERVICE_NAME", "sentinela-enrichment-worker")

def setup_tracing():
    resource = Resource(attributes={
        SERVICE_NAME: SERVICE_NAME_VAL
    })
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    return trace.get_tracer(SERVICE_NAME_VAL)

def inject_context(headers):
    """Injeta o contexto atual nos headers do Kafka."""
    TraceContextTextMapPropagator().inject(headers)

def extract_context(kafka_headers):
    """Extrai o contexto dos headers do Kafka (lista de tuplas)."""
    carrier = {k: v.decode("utf-8") if isinstance(v, bytes) else v for k, v in (kafka_headers or [])}
    return TraceContextTextMapPropagator().extract(carrier=carrier)
