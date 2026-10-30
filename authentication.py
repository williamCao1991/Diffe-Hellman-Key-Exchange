import json
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL_LABEL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_SIZE = 4096


def generate_nonce():
    return secrets.token_bytes(32).hex()


def encode_payload(payload):
    """Create the same compact JSON bytes every time."""
    try:
        message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError):
        return None
    if len(message) > MAX_MESSAGE_SIZE:
        return None
    return message


def sign_payload(private_key, payload):
    message = encode_payload(payload)
    if not isinstance(private_key, Ed25519PrivateKey) or message is None:
        return None
    return private_key.sign(message)


def encode_signed_message(payload, signature):
    if type(signature) is not bytes or len(signature) != 64:
        return None
    return encode_payload({"payload": payload, "signature": signature.hex()})


def decode_signed_message(message):
    """Read payload/signature, rejecting duplicate keys and oversized messages."""
    if type(message) is not bytes or len(message) > MAX_MESSAGE_SIZE:
        return None
    duplicates = []

    def read_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        envelope = json.loads(message.decode(), object_pairs_hook=read_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if duplicates or type(envelope) is not dict:
        return None
    if set(envelope) != {"payload", "signature"} or type(envelope["payload"]) is not dict:
        return None
    signature = envelope["signature"]
    if type(signature) is not str or len(signature) != 128:
        return None
    try:
        raw_signature = bytes.fromhex(signature)
    except ValueError:
        return None
    if len(raw_signature) != 64:
        return None
    return envelope["payload"], raw_signature


def valid_nonce(nonce):
    if type(nonce) is not str or len(nonce) != 64:
        return False
    try:
        return len(bytes.fromhex(nonce)) == 32
    except ValueError:
        return False
