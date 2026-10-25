from __future__ import annotations

import unittest
from unittest.mock import patch

from common.observability import _otlp_bearer_headers
from common.settings import AsgiServerSettings, ObservabilitySettings


class OtelRuntimeConfigTests(unittest.TestCase):
    def test_required_token_produces_bearer_header(self) -> None:
        settings = ObservabilitySettings(
            endpoint="https://telemetry.example.invalid",
            bearer_token="test-only-token",
        )
        self.assertEqual(
            _otlp_bearer_headers(settings),
            {"Authorization": "Bearer test-only-token"},
        )
        self.assertEqual(
            settings.signal_endpoint("traces"),
            "https://telemetry.example.invalid/v1/traces",
        )

    def test_missing_token_does_not_fall_back_to_legacy_headers(self) -> None:
        with patch.dict(
            "os.environ",
            {"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20obsolete"},
            clear=True,
        ):
            settings = ObservabilitySettings(endpoint="https://telemetry.example.invalid")
            with self.assertRaisesRegex(ValueError, "OTLP_BEARER_TOKEN"):
                _otlp_bearer_headers(settings)

    def test_asgi_worker_bounds(self) -> None:
        self.assertEqual(AsgiServerSettings().workers, 1)
        self.assertEqual(AsgiServerSettings(workers=3).workers, 3)
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            AsgiServerSettings(workers=0)


if __name__ == "__main__":
    unittest.main()
