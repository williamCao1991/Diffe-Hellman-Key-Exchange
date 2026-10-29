from Crypto.Util.number import getPrime, isPrime
import secrets

def generate_parameters(bits=16):


    p = getPrime(bits,randfunc= secrets.token_bytes)
    while not isPrime((p - 1) // 2):
        p = getPrime(bits,randfunc= secrets.token_bytes)
    q = (p - 1) // 2
    g = 2
    while pow(g, q, p) == 1:
        g += 1
    return p, q, g