
import base64
from cryptopals import *


key = random_key()
unknown = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK")


def encrypt_with_suffix(plain):
    plain = pkcs7_pad(plain + unknown)
    return encrypt_aes_ecb(plain, key)


block_size = ecb_block_size(encrypt_with_suffix)
suffix_length = ecb_append_length(encrypt_with_suffix, block_size)
plain = decrypt_ecb_suffix_by_byte(encrypt_with_suffix, suffix_length,
                                   block_size)
assert(plain == unknown)
