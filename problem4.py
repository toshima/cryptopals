
from cryptopals import *


with open("4.txt", 'r') as f:
    ciphers = [bytes.fromhex(line.strip()) for line in f]

expected = "Now that the party is jumping\n"

plains = [break_single_byte_xor(s) for s in ciphers]
assert(max(plains, key=text_score) == expected)
