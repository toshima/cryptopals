
import base64
from cryptopals import *


with open("10.txt", 'r') as f:
    cipher = base64.b64decode(f.read())

key = "YELLOW SUBMARINE"
iv = bytes(16)
expected = "I'm back and I'm ringin' the bell"
plain = decrypt_aes_cbc(cipher, key, iv)
assert(plain.decode().startswith(expected))

assert(encrypt_aes_cbc(plain, key, iv) == cipher)
