"""Tests for AES-256-GCM message envelopes and anti-replay protection."""

from __future__ import annotations

import unittest

from classical_simulation.message_envelope import (
    EnvelopeError,
    ReplayProtector,
    decrypt_payload,
    encrypt_payload,
)


class MessageEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.held_key = b"k" * 32
        self.held_path = "factory/line3"
        self.topic = "factory/line3/motor/speed"
        self.plaintext = b'{"rpm": 1500}'

    def test_authorised_branch_decrypts_round_trip(self) -> None:
        envelope = encrypt_payload(self.plaintext, self.topic, self.held_key, self.held_path, "motor-01", 1, 1)
        decrypted = decrypt_payload(envelope, self.topic, self.held_key, self.held_path)
        self.assertEqual(decrypted, self.plaintext)

    def test_sibling_branch_cannot_decrypt(self) -> None:
        envelope = encrypt_payload(self.plaintext, self.topic, self.held_key, self.held_path, "motor-01", 1, 1)
        wrong_held_path = "factory/line3/oven"
        with self.assertRaises(EnvelopeError):
            decrypt_payload(envelope, self.topic, self.held_key, wrong_held_path)

    def test_ciphertext_tampering_is_detected(self) -> None:
        envelope = encrypt_payload(self.plaintext, self.topic, self.held_key, self.held_path, "motor-01", 1, 1)
        # Flip base64 character in ciphertext
        raw_b64 = envelope["ciphertext"]
        tampered_b64 = ("A" if raw_b64[0] != "A" else "B") + raw_b64[1:]
        envelope["ciphertext"] = tampered_b64

        with self.assertRaises(EnvelopeError):
            decrypt_payload(envelope, self.topic, self.held_key, self.held_path)

    def test_topic_rebinding_is_detected(self) -> None:
        envelope = encrypt_payload(self.plaintext, self.topic, self.held_key, self.held_path, "motor-01", 1, 1)
        relocated_topic = "factory/line3/oven/temp"
        with self.assertRaises(EnvelopeError):
            decrypt_payload(envelope, relocated_topic, self.held_key, self.held_path)

    def test_replayed_valid_envelope_is_rejected(self) -> None:
        protector = ReplayProtector()
        envelope = encrypt_payload(self.plaintext, self.topic, self.held_key, self.held_path, "motor-01", 1, sequence=10)
        decrypt_payload(envelope, self.topic, self.held_key, self.held_path, replay_protector=protector)

        with self.assertRaises(EnvelopeError):
            decrypt_payload(envelope, self.topic, self.held_key, self.held_path, replay_protector=protector)


if __name__ == "__main__":
    unittest.main()

