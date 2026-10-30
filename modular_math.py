def modular_exponentiation(base, exponent, modulus):
    """Calculate base**exponent % modulus using square-and-multiply."""
    if (type(base) is not int or type(exponent) is not int or type(modulus) is not int or exponent < 0 or modulus <= 0):
        return "Reject"

    result = 1 % modulus
    base %= modulus
    while exponent > 0:
        if exponent % 2:
            result = result * base % modulus
        base = base * base % modulus
        exponent //= 2
    return result
