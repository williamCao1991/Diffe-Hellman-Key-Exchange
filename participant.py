import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from modular_math import modular_exponentiation


class Participant:
    def __init__(self, identity):
        self.identity = identity
        self.signing_private_key = Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_private_key.public_key()
        self.trusted_keys = {}
        self.pending = None
        self.seen_nonces = set()


def create_participant(identity):
    if identity not in ("Alice", "Bob"):
        return None
    return Participant(identity)


def provision_trusted_keys(alice, bob):
    if alice is None or bob is None:
        return
    alice.trusted_keys["Bob"] = bob.signing_public_key
    bob.trusted_keys["Alice"] = alice.signing_public_key


def generate_diffie_hellman_keys(p, g):
    if type(p) is not int or type(g) is not int or p < 5 or not 2 <= g <= p - 2:
        return None, None
    while True:
        private = secrets.randbelow(p - 3) + 2
        public = modular_exponentiation(g, private, p)
        if 2 <= public <= p - 2:
            return private, public


def generate_shared_secret(private, other_public, p):
    if (type(private) is not int or type(other_public) is not int or type(p) is not int
            or p < 5 or not 2 <= private <= p - 2
            or not 2 <= other_public <= p - 2):
        return None
    return modular_exponentiation(other_public, private, p)
