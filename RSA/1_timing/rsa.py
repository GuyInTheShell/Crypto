#!/usr/bin/env python
"""
With RSA, the size of the plaintext has basically no influence on the encryption or decryption time.
Timing attacks cannot be mounted based on a plaintext size

$ python -m timeit -s "import rsa" -- "rsa.encrypt(False)"                                                                                                                                                                                7:09
1000 loops, best of 5: 251 usec per loop

$ python -m timeit -s "import rsa" -- "rsa.encrypt(True)"                                                                                                                                                                                 7:14
1000 loops, best of 5: 217 usec per loop
"""
import optparse
import sys

import cryptography.hazmat.primitives.asymmetric.rsa as rsa

# Computed as global variables so that they don't have an impact on the time computation of the encryption/decryption
# algorithm

e = 65537
pkey = rsa.generate_private_key(e, 4096)
n = pkey.public_key().public_numbers().n
d = pkey.private_numbers().d


def process_params():
    parser = optparse.OptionParser()
    parser.add_option(
        "-s",
        "--short",
        dest="short",
        action="store_true",
        default=False,
        help="Whether to run the algorithm with a short number plaintext",
    )
    parser.add_option(
        "-l",
        "--long",
        dest="long",
        action="store_true",
        default=False,
        help=
        "Whether to run the algorithm with a long number plaintext (like n-2)",
    )
    parser.add_option(
        "-p",
        "--print",
        dest="print",
        action="store_true",
        default=False,
        help="Whether we should print the result to stdout",
    )
    parser.set_usage(help_message())
    return parser.parse_args()


def display_help():
    print(help_message())


def help_message():
    return (
        "This is a sample python app to compute noob level RSA encryption and decryption"
    )


def handle_opts(opts, args):
    if opts.short and opts.long:
        print(f"You have to chose either short or long")
        sys.exit(101)
    res = encrypt(opts.long)
    if opts.print:
        print(res)


def encrypt(long=False):
    m = 1023
    if long:
        m = n - 2
    return pow(m, e, n)


def main():
    opts, args = process_params()
    handle_opts(opts, args)


if __name__ == "__main__":
    main()
