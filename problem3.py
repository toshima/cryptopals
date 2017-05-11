
from cryptopals import *


plain = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
expected = "Cooking MC's like a pound of bacon"

plain = bytes.fromhex(plain)
assert(break_single_byte_xor(plain) == expected)
