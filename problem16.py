
from cryptopals import *


prefix = bytes("comment1=cooking%20MCs;userdata=", 'utf-8')
suffix = bytes(";comment2=%20like%20a%20pound%20of%20bacon", 'utf-8')

key = random_key()
iv = random_key()


def encrypt_userdata(data):
    data = data.replace(';', '').replace('=', '')
    plain = bytes(data, 'utf-8')
    plain = pkcs7_pad(prefix + plain + suffix)
    return encrypt_aes_cbc(plain, key, iv)


def is_admin(cipher):
    plain = decrypt_aes_cbc(cipher, key, iv)
    plain = pkcs7_unpad(plain)
    return ";admin=true;" in str(plain)


n = (len(prefix) // 16) * 16 + 16
data = 'A' * (n + 32 - len(prefix))
inject = ";admin=true"
while len(inject) < 16:
    inject = 'A' + inject

cipher = encrypt_userdata(data)
assert(not is_admin(cipher))

block = cipher[n:n+16]
block = xor(block, bytes(data[-16:], 'utf-8'))
block = xor(block, bytes(inject, 'utf-8'))
cipher = cipher[:n] + block + cipher[n+16:]

assert(is_admin(cipher))
