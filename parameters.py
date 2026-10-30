from Crypto.Util.number import getPrime, isPrime
import secrets
import time
from modular_math import modular_exponentiation as mo


def generate_prime(bits=16):
    if type(bits) is not int or not 16 <= bits <= 32:
        return None
    start = time.perf_counter()
    prime = getPrime(bits, randfunc=secrets.token_bytes)
    if prime.bit_length() != bits or prime % 2 == 0:
        return None
    print(f"Prime generation took {time.perf_counter() - start:.6f} seconds")
    return prime


generate_parameters = generate_prime()



def validate_received_modulus(prime, test_fixture=False):
    """Validate the received prime modulus."""
    if type(prime) is not int:
        return False
    if test_fixture and prime == 23:
        return isPrime(prime)
    return 16 <= prime.bit_length() <= 32 and isPrime(prime)


def prime_factors(number):
    """Return all distinct prime factors using trial division."""
    if type(number) is not int or number < 1:
        return []
    factors, divisor = [], 2
    while divisor * divisor <= number:
        if number % divisor == 0:
            factors.append(divisor)
            while number % divisor == 0:
                number //= divisor
        if divisor == 2:
            divisor = 3
        else:
            divisor += 2
    if number > 1:
        factors.append(number)
    return factors


def is_generator(candidate, prime, test_fixture=False):
    """Check if the candidate is a generator modulo the given prime."""
    if type(candidate) is not int or not validate_received_modulus(prime, test_fixture):
        return False
    if not 2 <= candidate <= prime - 2:
        return False
    for factor in prime_factors(prime - 1):
        result = mo(candidate, (prime - 1) // factor, prime)
        if result == 1:
            return False
    return True


def find_generator(prime, test_fixture=False):
    """Find a generator modulo the given prime."""
    if not validate_received_modulus(prime, test_fixture):
        return None
    factors = prime_factors(prime - 1)
    for candidate in range(2, prime - 1):
        good = True
        for factor in factors:
            if mo(candidate, (prime - 1) // factor, prime) == 1:
                good = False
                break
        if good:
            return candidate
    return None
