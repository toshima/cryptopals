
from cryptopals import *


a = "1c0111001f010100061a024b53535009181c"
b = "686974207468652062756c6c277320657965"
expected = "746865206b696420646f6e277420706c6179"

a = bytes.fromhex(a)
b = bytes.fromhex(b)
assert(xor(a, b).hex() == expected)
