"""Smoke tests for local software-simulation evaluation metrics."""

import unittest

from src.evaluation import measure


class EvaluationTests(unittest.TestCase):
    def test_measure_returns_positive_metrics(self):
        result = measure(iterations=2)
        self.assertEqual(result.iterations, 2)
        self.assertGreater(result.kdf_us, 0)
        self.assertGreater(result.encrypt_us, 0)
        self.assertGreater(result.decrypt_us, 0)
        self.assertGreater(result.ml_kem_onboarding_us, 0)
        self.assertGreater(result.lazy_rekey_us, 0)
        self.assertGreater(result.lkh_rekey_us, 0)
        self.assertGreater(result.lkh_rekey_messages, 0)
        self.assertGreater(result.telemetry_envelope_bytes, 0)
