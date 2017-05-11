
from cryptopals import *
import itertools

key = random_key()
prefix = random_length_key(5, 100)
suffix = random_length_key(5, 100)


def encrypt_with_prefix_suffix(plain):
    plain = prefix + plain + suffix
    plain = pkcs7_pad(plain)
    return encrypt_aes_ecb(plain, key)


block_size = ecb_block_size(encrypt_with_prefix_suffix)
append_length = ecb_append_length(encrypt_with_prefix_suffix, block_size)
prefix_length = ecb_prefix_length(encrypt_with_prefix_suffix, block_size)
suffix_length = append_length - prefix_length
plain = decrypt_ecb_suffix_by_byte(encrypt_with_prefix_suffix, suffix_length,
                                   block_size, prefix_length)
assert(plain == suffix)

