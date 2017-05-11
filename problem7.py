
import base64
from cryptopals import *


with open("7.txt", 'r') as f:
    cipher = base64.b64decode(f.read())

key = "YELLOW SUBMARINE"
expected = "I'm back and I'm ringin' the bell"
assert(decrypt_aes_ecb(cipher, key).decode().startswith(expected))
