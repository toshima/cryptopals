
from cryptopals import *


plain = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"
expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

plain = bytes(plain, 'utf-8')
key = bytes(key, 'utf-8')
assert(repeating_key_xor(plain, key).hex() == expected)
