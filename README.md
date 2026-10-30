# Diffie-Hellman Key Exchange

A classroom simulation of finite-field Diffie-Hellman with Ed25519 identity
signatures. The 16- to 32-bit module are intentionally small for testing and
are not secure for real usage. 


The tested cryptography versions are `cryptography==50.0.2` and
`pycryptodome==4.2.0`.

Run a 16-bit exchange and Eve's attack demonstration with `python main.py`.
Choose another size with `python main.py --bits 24`. Run the tests
with `python -m unittest -v tests`, or collect three timing trials per size
with `python main.py --benchmark`.
