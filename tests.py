import unittest

from authentication import decode_signed_message, encode_signed_message, sign_payload
from eve import tamper_signed_message
from modular_math import modular_exponentiation as mod_exp
from parameters import find_generator, generate_prime, is_generator, prime_factors, validate_received_modulus
from participant import create_participant, generate_shared_secret, provision_trusted_keys
from protocol import accept_finish, accept_initiation, accept_response, start_exchange


def pair():
    alice, bob = create_participant("Alice"), create_participant("Bob")
    provision_trusted_keys(alice, bob)
    return alice, bob


class ProjectTests(unittest.TestCase):
    """
    Test suite for the Diffie-Hellman key exchange protocol.
    Includes tests for mathematical operations, parameter validation,
    the full exchange protocol, and various attack scenarios.
    used assert methods from unittest.TestCase to verify the correctness of the implementation.
    """
    def test_math_and_parameters(self):
        self.assertEqual(mod_exp(5, 6, 23), 8)
        self.assertEqual(mod_exp(5, 0, 1), 0)
        self.assertEqual(mod_exp(5, -1, 23), "Reject")
        for base in range(-3, 4):
            self.assertEqual(mod_exp(base, 5, 13), pow(base, 5, 13))
        for bits in (16, 24, 32):
            prime = generate_prime(bits)
            self.assertEqual(prime.bit_length(), bits)
            self.assertTrue(validate_received_modulus(prime))
        self.assertIsNone(generate_prime(True))
        self.assertFalse(validate_received_modulus(32769))
        self.assertTrue(validate_received_modulus(23, True))
        self.assertEqual(prime_factors(22), [2, 11])
        self.assertEqual(prime_factors(65536), [2])
        self.assertTrue(is_generator(5, 23, True))
        self.assertFalse(is_generator(2, 23, True))
        self.assertEqual(find_generator(65537), 3)

    def test_exchange_and_shared_secret(self):
        """
        Test the full Diffie-Hellman key exchange protocol and verify that both bob and alice
        derive the same shared secret.
        """
        self.assertEqual(generate_shared_secret(6, 19, 23), 2)
        self.assertEqual(generate_shared_secret(15, 8, 23), 2)
        alice, bob = pair()
        init = start_exchange(alice, test_fixture=True)
        response = accept_initiation(bob, init, True)
        finish, secret_a = accept_response(alice, response)
        secret_b = accept_finish(bob, finish)
        self.assertEqual(secret_a, secret_b)

    def test_attacks_and_replays(self):
        """
        Test various attack scenarios and replay attacks to ensure the protocol's security.
        """
        for field, value in (("A", 9), ("p", 25), ("g", 2), ("initiator", "Eve")):
            alice, bob = pair()
            init = start_exchange(alice, test_fixture=True)
            self.assertIsNone(accept_initiation(bob, tamper_signed_message(init, field, value), True))
        alice, bob = pair()
        init = start_exchange(alice, test_fixture=True)
        response = accept_initiation(bob, init, True)
        payload = decode_signed_message(response)[0]
        changed = 19 if payload["transcript"]["B"] != 19 else 17
        self.assertIsNone(accept_response(alice, tamper_signed_message(response, "B", changed)))
        self.assertIsNone(alice.pending)

        alice, bob = pair()
        init = start_exchange(alice, test_fixture=True)
        response = accept_initiation(bob, init, True)
        finish, _ = accept_response(alice, response)
        accept_finish(bob, finish)
        self.assertIsNone(accept_initiation(bob, init, True))
        self.assertIsNone(accept_finish(bob, finish))
        self.assertIsNone(accept_response(alice, response))

    def test_old_messages_wrong_key_and_bad_json(self):
        """
        Test handling of old messages, wrong keys, and bad  JSON messages.
        """
        alice, bob = pair()
        init = start_exchange(alice, test_fixture=True)
        old_response = accept_initiation(bob, init, True)
        old_finish, _ = accept_response(alice, old_response)
        accept_finish(bob, old_finish)

        fresh_alice, fresh_bob = pair()
        fresh_init = start_exchange(fresh_alice, test_fixture=True)
        accept_initiation(fresh_bob, fresh_init, True)
        self.assertIsNone(accept_response(fresh_alice, old_response))
        self.assertIsNone(accept_finish(fresh_bob, old_finish))

        alice, bob = pair()
        eve = create_participant("Bob")
        alice.trusted_keys["Bob"] = eve.signing_public_key
        init = start_exchange(alice, test_fixture=True)
        response = accept_initiation(bob, init, True)
        self.assertIsNone(accept_response(alice, response))

        self.assertIsNone(decode_signed_message(b" " * 4097))
        duplicate = b'{"payload":{},"payload":{},"signature":"' + b"0" * 128 + b'"}'
        self.assertIsNone(decode_signed_message(duplicate))

    def test_forged_signature(self):
        alice, bob = pair()
        eve = create_participant("Alice")
        init = start_exchange(alice, test_fixture=True)
        payload = decode_signed_message(init)[0]
        forged = encode_signed_message(payload, sign_payload(eve.signing_private_key, payload))
        self.assertIsNone(accept_initiation(bob, forged, True))
        self.assertIsNone(decode_signed_message(b" " * 4097))
        duplicate = b'{"payload":{},"payload":{},"signature":"' + b"0" * 128 + b'"}'
        self.assertIsNone(decode_signed_message(duplicate))


if __name__ == "__main__":
    unittest.main()
