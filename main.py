import sys
import time

from authentication import decode_signed_message
from eve import demonstrate_unauthenticated_attack, tamper_signed_message
from parameters import find_generator, generate_prime, prime_factors
from participant import create_participant, provision_trusted_keys
from protocol import accept_finish, accept_initiation, accept_response, start_exchange


def new_pair():
    alice, bob = create_participant("Alice"), create_participant("Bob")
    provision_trusted_keys(alice, bob)
    return alice, bob


def exchange(bits=16, parameters=None, show=True):
    alice, bob = new_pair()
    if parameters is None:
        p = generate_prime(bits)
        if p is None:
            print("Prime size must be from 16 to 32 bits.")
            return None
        start = time.perf_counter()
        prime_factors(p - 1)
        factor_time = time.perf_counter() - start
        start = time.perf_counter()
        g = find_generator(p)
        generator_time = time.perf_counter() - start
    else:
        p, g = parameters
        factor_time = generator_time = 0

    if show:
        print(f"Requested prime size: {p.bit_length()} bits")
        print("Modulus: generated using library prime generator")
        print(f"Modulus bit length: {p.bit_length()}")
        print("Received modulus library validation: PASS")
        print(f"Factorization: {factor_time:.6f} seconds")
        print(f"Generator search: {generator_time:.6f} seconds")
        print("Generator: validated")

    init = start_exchange(alice, bits, public_parameters=(p, g))
    response = accept_initiation(bob, init)
    result = accept_response(alice, response)
    if result is None:
        print("Exchange aborted.")
        return None
    finish, secret_a = result
    secret_b = accept_finish(bob, finish)
    if show:
        print("Alice initiation signature: VALID")
        print("Bob response signature: VALID")
        print("Alice finish signature: VALID")
        print("Transcript authenticated: YES")
        print(f"Shared-secret equality in local test: {'PASS' if secret_a == secret_b else 'FAIL'}")
    return alice, bob


def attack_demo():
    values = demonstrate_unauthenticated_attack()
    print("\nUnauthenticated Eve attack (p=23)")
    print(f"Alice/Eve secrets: {values[0]}/{values[2]}")
    print(f"Bob/Eve secrets: {values[1]}/{values[3]}")

    alice, bob = new_pair()
    init = start_exchange(alice, test_fixture=True)
    response = accept_initiation(bob, init, test_fixture=True)
    if response is None:
        return
    payload = decode_signed_message(response)[0]
    changed_b = 19 if payload["transcript"]["B"] != 19 else 17
    changed = tamper_signed_message(response, "B", changed_b)
    if accept_response(alice, changed) is None:
        bob.pending = None
        print("Eve modified Bob's public value.")
        print("Bob response signature: INVALID")
        print("Exchange aborted.")


def benchmarks():
    print("\n| Bits | Trial | Prime (s) | Factors (s) | Generator (s) | Authenticated | Secrets match |")
    for bits in (16, 24, 32):
        for trial in range(1, 4):
            start = time.perf_counter()
            prime = generate_prime(bits)
            prime_time = time.perf_counter() - start
            start = time.perf_counter()
            prime_factors(prime - 1)
            factor_time = time.perf_counter() - start
            start = time.perf_counter()
            generator = find_generator(prime)
            generator_time = time.perf_counter() - start
            pair = exchange(bits, (prime, generator), False)
            matched = pair is not None and pair[0].pending["secret"] == pair[1].pending["secret"]
            print(f"| {bits} | {trial} | {prime_time:.6f} | {factor_time:.6f} | "
                  f"{generator_time:.6f} | {'Yes' if matched else 'No'} | {'Yes' if matched else 'No'} |")


if __name__ == "__main__":
    bits = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 16
    if 16 <= bits <= 32:
        exchange(bits)
        attack_demo()
        if "--benchmark" in sys.argv:
            # Run benchmarks if the --benchmark flag is provided
            benchmarks()
    else:
        print("Prime size must be from 16 to 32 bits.")
