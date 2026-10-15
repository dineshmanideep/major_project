import base64
import copy
import unittest

from src.message_envelope import (
    EnvelopeError,
    decrypt_payload,
    encrypt_payload,
    parse_envelope,
    serialise_envelope,
)


ROOT_KEY = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
LINE3 = "factory/line3"
TOPIC = "factory/line3/oven/temp"


class MessageEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.envelope = encrypt_payload(
            b'{"celsius": 182.4}', TOPIC, ROOT_KEY, LINE3, "esp32-oven-01", 1
        )

    def test_authorised_branch_decrypts_round_trip(self):
        payload = serialise_envelope(self.envelope)
        recovered = decrypt_payload(parse_envelope(payload), TOPIC, ROOT_KEY, LINE3)
        self.assertEqual(recovered, b'{"celsius": 182.4}')

    def test_sibling_branch_cannot_decrypt(self):
        with self.assertRaises(EnvelopeError):
            decrypt_payload(self.envelope, TOPIC, ROOT_KEY, "factory/line3/motor")

    def test_ciphertext_tampering_is_detected(self):
        modified = copy.deepcopy(self.envelope)
        ciphertext = bytearray(base64.b64decode(modified["ciphertext"]))
        ciphertext[0] ^= 1
        modified["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        with self.assertRaisesRegex(EnvelopeError, "authentication failed"):
            decrypt_payload(modified, TOPIC, ROOT_KEY, LINE3)

    def test_topic_rebinding_is_detected(self):
        with self.assertRaisesRegex(EnvelopeError, "authentication failed"):
            decrypt_payload(self.envelope, "factory/line3/oven/pressure", ROOT_KEY, LINE3)

    def test_sender_metadata_tampering_is_detected(self):
        modified = copy.deepcopy(self.envelope)
        modified["sender_id"] = "attacker"
        with self.assertRaisesRegex(EnvelopeError, "authentication failed"):
            decrypt_payload(modified, TOPIC, ROOT_KEY, LINE3)
