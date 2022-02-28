#!/usr/bin/env python
"""
RSA is based on the fact that we can easily find a relation of the form
(m**e)**d mod n = m

where
- m is the plaintext message
- m**e is the ciphertext
- e is the public exponent
- d is the private exponent
- n is the modulus

We chose n = p*q where p and q are 2 large primes
e is a prime number for simplicity (generally 2**16 + 1 = 65537)

if we call phi the euclidean totient function, and because phi is multiplicative
    phi(n) = phi(p) * phi(q)
and since p and q are prime (and therefore coprime), we have
    phi(n) = (p-1) * (q-1)

Furthermore, Euler's theorem states that x ** phi(n) = 1 mod n if x and n are coprime
This holds for e and n since n's factors are only p and q, and p,q and e are prime 

So let's take the starting point
    (m**e)**d = m ** (e*d)
if we chose e*d so that e*d = 1 mod phi(n), then
    m ** (e*d)  = m ** (1 + k*phi(n))   mod n
                = m * (m**phi(n))**k    mod n
                = m * (1)**k            mod n
                = m                     mod n

from the choice e*d = 1 mod phi(n) we get that
    d is the modular inverse of e modulo phi(n)
"""
import optparse
import sys


def process_params():
    parser = optparse.OptionParser()
    parser.add_option(
        "-o",
        "--operation",
        dest="operation",
        default="e",
        help="Whether to encrypt (e) or decrypt (d)",
        metavar="OPERATION",
    )
    parser.set_usage(help_message())
    return parser.parse_args()


def display_help():
    print(help_message())


def help_message():
    return (
        "This is a sample python app to compute noob level RSA encryption and decryption\n\n"
        "This program handles only single digit encryption because we chose a very small n. "
        "And the plaintext must be smaller than n\n\n")


def handle_opts(opts, args):
    if len(args) != 1:
        print("Expecting a single digit to encrypt/decrypt in parameter")
        display_help()
        sys.exit(101)
    if opts.operation in ["d", "decrypt"]:
        res = decrypt(args)
        print(f"The decrypted value of {args[0]} is {res}")
    else:
        res = encrypt(args)
        print(f"The encrypted value of {args[0]} is {res}")


def rsa_parameters():
    p = 3  # prime
    q = 5  # prime
    n = p * q  # 15
    # There ar p-1 positive integers smaller than p that are coprime with p (since p is prime). phi(p) = p-1
    # There ar q-1 positive integers smaller than q that are coprime with q (since q is prime). phi(q) = q-1
    # Knowing that the phi function (euclidean totient) is multiplication, phi(n) = phi(p)*phi(q)
    phi = (p - 1) * (q - 1)  # 8
    e = 7  # needs to be coprime with phi. we take a large e that is prime and smaller than phi and it works
    # Because we chose e and n to be coprime, Euler's theorem tells us that
    # e**phi(n) == 1 mod n
    d = pow(e, -1, phi)

    return n, e, d


def encrypt(args):
    n, e, _ = rsa_parameters()
    return int(args[0])**e % n


def decrypt(args):
    n, _, d = rsa_parameters()
    return int(args[0])**d % n


def efficient_encrypt(args):
    n, e, _ = rsa_parameters()
    return pow(int(args[0]), e, n)


def efficient_decrypt(args):
    n, _, d = rsa_parameters()
    return pow(int(args[0]), d, n)


def main():
    opts, args = process_params()
    handle_opts(opts, args)


if __name__ == "__main__":
    main()
