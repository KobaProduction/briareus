from __future__ import annotations

import atexit
import logging
import queue
import threading
import time
import urllib.parse
from collections.abc import Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, ExitStack, contextmanager, nullcontext, suppress

from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, SpanKind

from .account_contracts import InvocationEvent
from .management_client import ManagementClient
from .settings import ObservabilitySettings

logger = logging.getLogger("mcp_bridge.observability")
_AUDIT_TRACER = trace.get_tracer("mcp-bridge.management-audit")
if not logger.handlers:
    _console_handler = logging.StreamHandler()
    _console_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(_console_handler)
logger.setLevel(logging.INFO)
logger.propagate = False


class ObservabilitySink:
    """Best-effort destination for runtime, logs, spans, and MCP invocation metrics."""

    def record_runtime_started(self, scope: str) -> None:
        raise NotImplementedError

    def record_runtime_heartbeat(self, scope: str) -> None:
        raise NotImplementedError

    def record_invocation(
        self,
        event: InvocationEvent,
        *,
        audit: bool = True,
    ) -> None:
        raise NotImplementedError

    def trace_span(
        self,
        name: str,
        attributes: Mapping[str, object] | None = None,
    ) -> AbstractContextManager[Span | None]:
        raise NotImplementedError


class CompositeObservabilitySink(ObservabilitySink):
    """Fan out one observation to independent sinks without coupling failures."""

    def __init__(self, sinks: Iterable[ObservabilitySink]) -> None:
        self.sinks = tuple(sinks)

    def record_runtime_started(self, scope: str) -> None:
        for sink in self.sinks:
            try:
                sink.record_runtime_started(scope)
            except Exception:
                logger.exception("Observability runtime-start sink failed scope=%s", scope)

    def record_runtime_heartbeat(self, scope: str) -> None:
        for sink in self.sinks:
            try:
                sink.record_runtime_heartbeat(scope)
            except Exception:
                logger.exception("Observability heartbeat sink failed scope=%s", scope)

    def record_invocation(
        self,
        event: InvocationEvent,
        *,
        audit: bool = True,
    ) -> None:
        for sink in self.sinks:
            try:
                sink.record_invocation(event, audit=audit)
            except Exception:
                logger.exception(
                    "Observability invocation sink failed scope=%s tool=%s",
                    event.module,
                    event.tool,
                )

    @contextmanager
    def trace_span(
        self,
        name: str,
        attributes: Mapping[str, object] | None = None,
    ) -> Iterator[Span | None]:
        with ExitStack() as stack:
            active_span: Span | None = None
            for sink in self.sinks:
                try:
                    candidate = stack.enter_context(sink.trace_span(name, attributes))
                    if candidate is not None:
                        active_span = candidate
                except Exception:
                    logger.exception("Observability span sink failed span=%s", name)
            yield active_span


class ManagementAuditSink(ObservabilitySink):
    """Batch redacted invocation history into Management without blocking tool calls."""

    _MAX_BATCH = 32
    _MAX_QUEUE = 1024
    _BATCH_WINDOW_SECONDS = 0.05

    def __init__(self, management: ManagementClient) -> None:
        self.management = management
        self._queue: queue.Queue[tuple[InvocationEvent, float]] = queue.Queue(
            maxsize=self._MAX_QUEUE
        )
        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self._run,
            name="management-audit-batch",
            daemon=True,
        )
        self._worker.start()
        atexit.register(self.close)

    def record_runtime_started(self, scope: str) -> None:
        del scope

    def record_runtime_heartbeat(self, scope: str) -> None:
        del scope

    def record_invocation(
        self,
        event: InvocationEvent,
        *,
        audit: bool = True,
    ) -> None:
        if not audit or self._stop.is_set():
            return
        try:
            self._queue.put_nowait((event, time.monotonic()))
        except queue.Full:
            logger.warning(
                "Management audit queue full; dropping event scope=%s tool=%s",
                event.module,
                event.tool,
            )

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                first = self._queue.get(timeout=self._BATCH_WINDOW_SECONDS)
            except queue.Empty:
                continue
            batch = [first]
            deadline = time.monotonic() + self._BATCH_WINDOW_SECONDS
            while len(batch) < self._MAX_BATCH:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break
            events = [item[0] for item in batch]
            oldest_wait_ms = (time.monotonic() - batch[0][1]) * 1000
            try:
                with _AUDIT_TRACER.start_as_current_span(
                    "management.audit.batch",
                    kind=SpanKind.INTERNAL,
                    attributes={
                        "audit.batch.size": len(events),
                        "audit.queue.depth": self._queue.qsize(),
                        "audit.queue.oldest_wait_ms": oldest_wait_ms,
                    },
                ):
                    self.management.record_invocations(events)
            except Exception:
                logger.exception(
                    "Management audit batch failed count=%d",
                    len(events),
                )
            finally:
                for _ in batch:
                    self._queue.task_done()

    def close(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self._worker.join(timeout=1.0)

    def trace_span(
        self,
        name: str,
        attributes: Mapping[str, object] | None = None,
    ) -> AbstractContextManager[Span | None]:
        del name, attributes
        return nullcontext(None)


class _ExcludeOpenTelemetryLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.startswith("opentelemetry")


def _parse_key_values(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item or "=" not in item:
            continue
        key, raw_value = item.split("=", 1)
        key = urllib.parse.unquote(key.strip())
        decoded = urllib.parse.unquote(raw_value.strip())
        if key:
            result[key] = decoded
    return result


def _resource_attributes(
    settings: ObservabilitySettings,
    scope: str,
) -> dict[str, object]:
    attributes: dict[str, object] = dict(_parse_key_values(settings.resource_attributes))
    attributes.update(
        {
            "service.name": settings.service_name,
            "service.version": settings.service_version,
            "service.instance.id": settings.resolved_instance_id,
            "deployment.environment.name": settings.environment,
            "mcp.scope": scope,
        }
    )
    return attributes


def _logging_level(value: str) -> int:
    level = logging.getLevelName(value.upper())
    return level if isinstance(level, int) else logging.INFO


def _otlp_bearer_headers(settings: ObservabilitySettings) -> dict[str, str]:
    """Build one SDK header mapping without accepting legacy, preformatted headers."""
    if not settings.bearer_token:
        raise ValueError("OTLP_BEARER_TOKEN is required when OTLP_ENDPOINT is set")
    return {"Authorization": f"Bearer {settings.bearer_token}"}


class OpenTelemetrySink(ObservabilitySink):
    """Official OpenTelemetry SDK pipeline for logs, traces, and metrics."""

    def __init__(self, scope: str, settings: ObservabilitySettings) -> None:
        self.scope = scope
        self.settings = settings
        self._shutdown = False
        self._attached_loggers: list[logging.Logger] = []

        headers = _otlp_bearer_headers(settings)
        resource = Resource.create(_resource_attributes(settings, scope))

        self.logger_provider = LoggerProvider(resource=resource)
        self.logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                OTLPLogExporter(
                    endpoint=settings.signal_endpoint("logs"),
                    headers=headers,
                    timeout=settings.timeout_seconds,
                )
            )
        )
        set_logger_provider(self.logger_provider)

        self.tracer_provider = TracerProvider(resource=resource)
        self.tracer_provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=settings.signal_endpoint("traces"),
                    headers=headers,
                    timeout=settings.timeout_seconds,
                )
            )
        )
        trace.set_tracer_provider(self.tracer_provider)
        self.tracer = self.tracer_provider.get_tracer(f"mcp-bridge.{scope}")

        metric_exporter = OTLPMetricExporter(
            endpoint=settings.signal_endpoint("metrics"),
            headers=headers,
            timeout=settings.timeout_seconds,
        )
        self.metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=settings.metric_export_interval_ms,
            export_timeout_millis=settings.timeout_ms,
        )
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[self.metric_reader],
        )
        metrics.set_meter_provider(self.meter_provider)
        self.meter = self.meter_provider.get_meter(f"mcp-bridge.{scope}")

        self.runtime_started = self.meter.create_counter(
            "mcp.runtime.started",
            unit="{event}",
            description="Runtime process starts.",
        )
        self.runtime_up = self.meter.create_gauge(
            "mcp.runtime.up",
            unit="1",
            description="Runtime availability at observation time.",
        )
        self.tool_calls = self.meter.create_counter(
            "mcp.tool.calls",
            unit="{call}",
            description="MCP tool calls.",
        )
        self.tool_errors = self.meter.create_counter(
            "mcp.tool.errors",
            unit="{error}",
            description="MCP tool call errors.",
        )
        self.tool_duration = self.meter.create_histogram(
            "mcp.tool.duration",
            unit="ms",
            description="Observed MCP tool call duration.",
        )

        self._install_logging_handler()
        atexit.register(self.shutdown)

        logger.info(
            "OpenTelemetry configured scope=%s service=%s instance=%s signals=logs,traces,metrics",
            scope,
            settings.service_name,
            settings.resolved_instance_id,
        )

    def _install_logging_handler(self) -> None:
        handler = LoggingHandler(
            level=_logging_level(self.settings.log_level),
            logger_provider=self.logger_provider,
        )
        handler.addFilter(_ExcludeOpenTelemetryLogs())
        self.logging_handler = handler

        root = logging.getLogger()
        if root.level != logging.NOTSET and root.level > handler.level:
            root.setLevel(handler.level)
        root.addHandler(handler)
        self._attached_loggers.append(root)

        for name in (
            "uvicorn",
            "uvicorn.error",
            "uvicorn.access",
            "fastmcp",
            "mcp_bridge.observability",
        ):
            target = logging.getLogger(name)
            if not target.propagate and handler not in target.handlers:
                target.addHandler(handler)
                self._attached_loggers.append(target)

    def trace_span(
        self,
        name: str,
        attributes: Mapping[str, object] | None = None,
    ) -> AbstractContextManager[Span | None]:
        return self.tracer.start_as_current_span(
            name,
            kind=SpanKind.INTERNAL,
            attributes=dict(attributes or {}),
            record_exception=True,
            set_status_on_exception=True,
        )

    def record_runtime_started(self, scope: str) -> None:
        attributes = {"mcp.scope": scope}
        self.runtime_started.add(1, attributes)
        self.runtime_up.set(1, attributes)
        with self.trace_span("mcp.runtime.start", attributes):
            logger.info(
                "OpenTelemetry runtime started scope=%s service=%s",
                scope,
                self.settings.service_name,
            )
        if self.force_flush():
            logger.info("OpenTelemetry startup signals flushed scope=%s", scope)
        else:
            logger.warning("OpenTelemetry startup flush timed out scope=%s", scope)

    def record_runtime_heartbeat(self, scope: str) -> None:
        self.runtime_up.set(1, {"mcp.scope": scope})

    def record_invocation(
        self,
        event: InvocationEvent,
        *,
        audit: bool = True,
    ) -> None:
        del audit
        attributes: dict[str, object] = {
            "mcp.scope": self.scope,
            "mcp.module": event.module,
            "mcp.tool": event.tool,
            "mcp.status": event.status,
        }
        if event.provider:
            attributes["mcp.provider"] = event.provider
        if event.error_type:
            attributes["error.type"] = event.error_type

        self.tool_calls.add(1, attributes)
        self.tool_duration.record(event.duration_ms, attributes)
        if event.status == "error":
            self.tool_errors.add(1, attributes)

    def force_flush(self) -> bool:
        timeout = self.settings.timeout_ms
        logs_ok = self.logger_provider.force_flush(timeout_millis=timeout)
        traces_ok = self.tracer_provider.force_flush(timeout_millis=timeout)
        metrics_ok = self.meter_provider.force_flush(timeout_millis=timeout)
        return bool(logs_ok and traces_ok and metrics_ok)

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        for target in self._attached_loggers:
            with suppress(Exception):
                target.removeHandler(self.logging_handler)
        try:
            self.force_flush()
        except Exception:
            logger.exception(
                "OpenTelemetry force_flush failed during shutdown scope=%s",
                self.scope,
            )
        self.logger_provider.shutdown()
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()


def build_observability(
    scope: str,
    *,
    management: ManagementClient | None = None,
    settings: ObservabilitySettings | None = None,
) -> CompositeObservabilitySink:
    configured = settings or ObservabilitySettings()
    sinks: list[ObservabilitySink] = []
    if management is not None:
        sinks.append(ManagementAuditSink(management))
    if configured.enabled:
        try:
            sinks.append(OpenTelemetrySink(scope, configured))
        except Exception:
            logger.exception(
                "OpenTelemetry initialization failed scope=%s; continuing without exporter",
                scope,
            )
    else:
        logger.info(
            "OpenTelemetry disabled scope=%s reason=endpoint_not_configured",
            scope,
        )
    return CompositeObservabilitySink(sinks)


def announce_runtime_started(sink: ObservabilitySink, scope: str) -> None:
    """Emit startup signals immediately and keep runtime-up fresh."""

    def run() -> None:
        sink.record_runtime_started(scope)
        while True:
            time.sleep(60)
            sink.record_runtime_heartbeat(scope)

    thread = threading.Thread(
        target=run,
        name=f"observability-{scope}-runtime",
        daemon=True,
    )
    thread.start()
