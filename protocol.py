from cryptography.exceptions import InvalidSignature
from authentication import (
    PROTOCOL_LABEL, decode_signed_message, encode_payload, encode_signed_message,
    generate_nonce, sign_payload, valid_nonce,
)
from parameters import find_generator, generate_prime, is_generator, validate_received_modulus
from participant import generate_diffie_hellman_keys, generate_shared_secret

INIT_FIELDS = {"protocol", "message_type", "initiator", "responder", "p", "g", "A", "nonce_A"}
MESSAGE_FIELDS = {"protocol", "message_type", "transcript"}
TRANSCRIPT_FIELDS = {
    "protocol", "initiator", "responder", "p", "g", "A", "B", "nonce_A", "nonce_B"
}


def _read(message, kind, fields, key):
    decoded = decode_signed_message(message)
    if decoded is None:
        return None
    payload, signature = decoded
    if set(payload) != fields or payload.get("protocol") != PROTOCOL_LABEL:
        return None
    if payload.get("message_type") != kind or key is None:
        return None
    try:
        key.verify(signature, encode_payload(payload))
    except (InvalidSignature, TypeError):
        return None
    return payload


def _valid_transcript(data):
    if type(data) is not dict or set(data) != TRANSCRIPT_FIELDS:
        return False
    if data["protocol"] != PROTOCOL_LABEL or data["initiator"] != "Alice" or data["responder"] != "Bob":
        return False
    for name in ("p", "g", "A", "B"):
        if type(data[name]) is not int:
            return False
    p = data["p"]
    return (valid_nonce(data["nonce_A"]) and valid_nonce(data["nonce_B"])
            and 2 <= data["A"] <= p - 2 and 2 <= data["B"] <= p - 2)


def _sign(person, payload):
    signature = sign_payload(person.signing_private_key, payload)
    return encode_signed_message(payload, signature)


def _reject(person):
    person.pending = None
    return None


def start_exchange(alice, bits=16, test_fixture=False, public_parameters=None):
    if alice is None or alice.identity != "Alice":
        return None
    if alice.pending is not None and alice.pending["state"] == "response":
        return None
    if test_fixture:
        p, g = 23, 5
    elif public_parameters is not None:
        p, g = public_parameters
        if not validate_received_modulus(p) or not is_generator(g, p):
            return None
    else:
        p = generate_prime(bits)
        if p is None:
            return None
        g = find_generator(p)
    private, public = generate_diffie_hellman_keys(p, g)
    payload = {
        "protocol": PROTOCOL_LABEL, "message_type": "init",
        "initiator": "Alice", "responder": "Bob", "p": p, "g": g,
        "A": public, "nonce_A": generate_nonce(),
    }
    alice.pending = {"state": "response", "private": private, "init": payload}
    return _sign(alice, payload)


def accept_initiation(bob, message, test_fixture=False):
    if bob is None or bob.identity != "Bob":
        return None
    if bob.pending is not None and bob.pending["state"] == "finish":
        return None
    payload = _read(message, "init", INIT_FIELDS, bob.trusted_keys.get("Alice"))
    if payload is None or payload["initiator"] != "Alice" or payload["responder"] != "Bob":
        return None
    for name in ("p", "g", "A"):
        if type(payload[name]) is not int:
            return None
    nonce, p, g, public_a = payload["nonce_A"], payload["p"], payload["g"], payload["A"]
    if nonce in bob.seen_nonces or not valid_nonce(nonce):
        return None
    if not validate_received_modulus(p, test_fixture) or not is_generator(g, p, test_fixture):
        return None
    if not 2 <= public_a <= p - 2:
        return None

    private, public_b = generate_diffie_hellman_keys(p, g)
    transcript = {
        "protocol": PROTOCOL_LABEL, "initiator": "Alice", "responder": "Bob",
        "p": p, "g": g, "A": public_a, "B": public_b,
        "nonce_A": nonce, "nonce_B": generate_nonce(),
    }
    response = {"protocol": PROTOCOL_LABEL, "message_type": "response", "transcript": transcript}
    bob.pending = {"state": "finish", "private": private, "transcript": transcript}
    bob.seen_nonces.add(nonce)
    return _sign(bob, response)


def accept_response(alice, message):
    if alice is None or alice.pending is None or alice.pending["state"] != "response":
        return None
    payload = _read(message, "response", MESSAGE_FIELDS, alice.trusted_keys.get("Bob"))
    if payload is None or not _valid_transcript(payload.get("transcript")):
        return _reject(alice)
    transcript = payload["transcript"]
    for name in ("p", "g", "A", "nonce_A"):
        if transcript[name] != alice.pending["init"][name]:
            return _reject(alice)

    finish = {"protocol": PROTOCOL_LABEL, "message_type": "finish", "transcript": transcript}
    secret = generate_shared_secret(alice.pending["private"], transcript["B"], transcript["p"])
    alice.pending = {"state": "done", "transcript": transcript, "secret": secret}
    return _sign(alice, finish), secret


def accept_finish(bob, message):
    if bob is None or bob.pending is None or bob.pending["state"] != "finish":
        return None
    payload = _read(message, "finish", MESSAGE_FIELDS, bob.trusted_keys.get("Alice"))
    if payload is None or payload["transcript"] != bob.pending["transcript"]:
        return _reject(bob)
    transcript = bob.pending["transcript"]
    secret = generate_shared_secret(bob.pending["private"], transcript["A"], transcript["p"])
    bob.pending = {"state": "done", "transcript": transcript, "secret": secret}
    return secret
