
from cryptopals import *


a = bytes("ICE ICE BABY\x04\x04\x04\x04", 'utf-8')
b = bytes("ICE ICE BABY\x05\x05\x05\x05", 'utf-8')
c = bytes("ICE ICE BABY\x01\x02\x03\x04", 'utf-8')

expected = bytes("ICE ICE BABY", 'utf-8')

assert(pkcs7_unpad(a) == expected)

try:
    pkcs7_unpad(b)
    raise AssertionError()
except ValueError:
    pass

try:
    pkcs7_unpad(c)
    raise AssertionError()
except ValueError:
    pass
