
from cryptopals import *


s = "YELLOW SUBMARINE"
expected = "YELLOW SUBMARINE\x04\x04\x04\x04"

s = bytes(s, 'utf-8')
assert(pkcs7_pad(s, 20).decode() == expected)
