
import base64
from cryptopals import *


a = bytes("this is a test", 'utf-8')
b = bytes("wokka wokka!!!", 'utf-8')
assert(hamming_distance(a, b) == 37)


def break_repeating_key_xor(cipher):
    cipher = base64.b64decode(cipher)

    def score(keysize):
        return hamming_distance(cipher, cipher[keysize:])

    keysize = min(range(2, 41), key=score)
    blocks = [cipher[i::keysize] for i in range(keysize)]
    plains = [break_single_byte_xor(s) for s in blocks]
    return ''.join(''.join(plain[i] for plain in plains if i < len(plain))
                   for i in range(len(plains[0])))


with open("6.txt", 'r') as f:
    cipher = f.read().strip()

expected = "I'm back and I'm ringin' the bell"
assert(break_repeating_key_xor(cipher).startswith(expected))
