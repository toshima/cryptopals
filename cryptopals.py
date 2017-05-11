
from Crypto.Cipher import AES
import itertools
import secrets


def xor(bytes1, bytes2):
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))


def byte_range():
    for i in range(256):
        yield bytes([i])


def break_single_byte_xor(cipher):
    plains = []
    for b in byte_range():
        key = b * len(cipher)
        try:
            plain = xor(cipher, key).decode()
            plains.append(plain)
        except UnicodeDecodeError:
            pass

    # if plains: print(xor(cipher, bytes(max(plains, key=text_score), 'utf-8')))
    return max(plains, key=text_score) if plains else None


def text_score(s):
    def score_char(c):
        return 'a' <= c <= 'z' or 'A' <= c <= 'Z' or c in " \n"
    return sum(map(score_char, s)) if s is not None else -1


def repeating_key_xor(plain, key):
    return xor(plain, key * len(plain))


def hamming_distance(a, b):
    def bitcount(x):
        return bitcount(x & (x-1)) + 1 if x else 0
    return sum(bitcount(x) for x in xor(a, b))


def encrypt_aes_ecb(plain, key):
    return AES.AESCipher(key, AES.MODE_ECB).encrypt(plain)


def decrypt_aes_ecb(cipher, key):
    return AES.AESCipher(key, AES.MODE_ECB).decrypt(cipher)


def pkcs7_pad(s, block_size=16):
    n = block_size - len(s) % block_size
    return s + bytes([n] * n)


def pkcs7_unpad(s):
    n = s[-1]
    if not 0 < n <= len(s) or s[-n:] != bytes([n] * n):
        raise ValueError("Invalid padding")
    return s[:-n]


def encrypt_aes_cbc(plain, key, iv):
    cipher = b''
    for block in split_blocks(plain):
        iv = encrypt_aes_ecb(xor(block, iv), key)
        cipher += iv
    return cipher


def decrypt_aes_cbc(cipher, key, iv):
    plain = b''
    for block in split_blocks(cipher):
        plain += xor(decrypt_aes_ecb(block, key), iv)
        iv = block
    return plain


def split_blocks(s, block_size=16):
    assert(len(s) % block_size == 0)
    return [s[i:i+block_size] for i in range(0, len(s), block_size)]


def random_key(length=16):
    return secrets.token_bytes(length)


def random_length_key(lo, hi):
    length = secrets.choice(range(lo, hi+1))
    return random_key(length)


def ecb_block_size(encrypt_func):
    for n in itertools.count():
        plain1 = b'A' * n
        plain2 = b'A' * (n+1)
        cipher1 = encrypt_func(plain1)
        cipher2 = encrypt_func(plain2)
        if len(cipher1) < len(cipher2):
            return len(cipher2) - len(cipher1)


def ecb_append_length(encrypt_func, block_size):
    block_size = ecb_block_size(encrypt_func)
    for n in range(block_size):
        plain1 = b'A' * n
        plain2 = b'A' * (n+1)
        cipher1 = encrypt_func(plain1)
        cipher2 = encrypt_func(plain2)
        if len(cipher1) < len(cipher2):
            return len(cipher1) - n - 1


def ecb_prefix_length(encrypt_func, block_size):
    for n in range(2*block_size, 3*block_size):
        plain = b'A' * n
        cipher = encrypt_func(plain)
        blocks = split_blocks(cipher, block_size)
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                return i * block_size - len(plain) % block_size


def decrypt_ecb_suffix_by_byte(encrypt_func, suffix_length, block_size,
                               prefix_length=0):
    suffix = b''
    for i in range(suffix_length):
        plain_length = (-prefix_length - i - 1) % block_size
        plain1 = b'A' * plain_length
        cipher1 = encrypt_func(plain1)
        for b in byte_range():
            plain2 = plain1 + suffix + b
            cipher2 = encrypt_func(plain2)
            n = prefix_length + len(plain2)
            if cipher1[n-block_size:n] == cipher2[n-block_size:n]:
                suffix += b
                break
    return suffix
