import sys
import types
from unittest.mock import MagicMock

mock_trace = MagicMock()
mock_trace.get_tracer.return_value.start_as_current_span.return_value.__enter__.return_value = MagicMock()

mock_otel = types.SimpleNamespace(trace=mock_trace)
sys.modules["opentelemetry"] = mock_otel

mock_otel_trace = types.SimpleNamespace(get_tracer=mock_trace.get_tracer, set_tracer_provider=MagicMock())
sys.modules["opentelemetry.trace"] = mock_otel_trace

mock_otel_sdk = MagicMock()
sys.modules["opentelemetry.sdk"] = mock_otel_sdk
sys.modules["opentelemetry.sdk.trace"] = mock_otel_sdk
sys.modules["opentelemetry.sdk.trace.export"] = mock_otel_sdk
sys.modules["opentelemetry.sdk.resources"] = mock_otel_sdk

mock_otel_exporter = MagicMock()
sys.modules["opentelemetry.exporter"] = mock_otel_exporter
sys.modules["opentelemetry.exporter.otlp"] = mock_otel_exporter
sys.modules["opentelemetry.exporter.otlp.proto"] = mock_otel_exporter
sys.modules["opentelemetry.exporter.otlp.proto.grpc"] = mock_otel_exporter
sys.modules["opentelemetry.exporter.otlp.proto.grpc.trace_exporter"] = mock_otel_exporter

mock_otel_prop = MagicMock()
sys.modules["opentelemetry.trace.propagation"] = mock_otel_prop
sys.modules["opentelemetry.trace.propagation.tracecontext"] = mock_otel_prop
