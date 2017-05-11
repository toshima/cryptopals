
import secrets
from cryptopals import *


use_ecb = secrets.choice([False, True])


def encrypt_ecb_or_cbc(plain):
    key = random_key()
    prefix = random_length_key(5, 10)
    suffix = random_length_key(5, 10)
    plain = pkcs7_pad(prefix + plain + suffix)
    if use_ecb:
        cipher = encrypt_aes_ecb(plain, key)
    else:
        iv = random_key()
        cipher = encrypt_aes_cbc(plain, key, iv)
    return cipher


def is_ecb(encrypt_func, block_size=16):
    plain = bytes(block_size * 3)
    cipher = encrypt_func(plain)
    blocks = split_blocks(cipher)
    return blocks[1] == blocks[2]


assert(is_ecb(encrypt_ecb_or_cbc) == use_ecb)
