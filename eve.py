from authentication import decode_signed_message, encode_signed_message
from modular_math import modular_exponentiation as mod_exp


def demonstrate_unauthenticated_attack():
    """
    Demonstrate an unauthenticated attack on the Diffie-Hellman key exchange protocol.
    Eve intercepts the messages between Alice and Bob and computes the shared secrets
    independently, effectively breaking the security of the exchange.
    """
    p, g, a, b = 23, 5, 6, 15
    alice, bob = mod_exp(g, a, p), mod_exp(g, b, p)
    eve_a, eve_b = mod_exp(g, 3, p), mod_exp(g, 7, p)
    return (mod_exp(eve_a, a, p), mod_exp(eve_b, b, p),
            mod_exp(alice, 3, p), mod_exp(bob, 7, p))


def tamper_signed_message(message, field, value):
    """
    Tamper with a signed message by modifying a specific field in the payload.
    returns the re-encoded message with the original signature, or None if the message is invalid.
    """
    decoded = decode_signed_message(message)
    if decoded is None:
        return None
    payload, signature = decoded
    target = payload.get("transcript", payload)
    if type(target) is not dict or field not in target:
        return None
    target[field] = value
    return encode_signed_message(payload, signature)
