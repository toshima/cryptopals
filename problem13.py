
from cryptopals import *


def parse_profile(profile):
    return dict(kv.split('=') for kv in profile.split('&'))


a = "foo=bar&baz=qux&zap=zazzle"
expected = {
    "foo": "bar",
    "baz": "qux",
    "zap": "zazzle",
}
assert(parse_profile(a) == expected)


def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return "email={}&uid=10&role=user".format(email)


a = "foo@bar.com"
expected = "email=foo@bar.com&uid=10&role=user"
assert(profile_for(a) == expected)


key = random_key()


def encrypt_profile(profile):
    plain = bytes(profile, 'utf-8')
    plain = pkcs7_pad(plain)
    return encrypt_aes_ecb(plain, key)


def decrypt_profile(cipher):
    plain = decrypt_aes_ecb(cipher, key)
    plain = pkcs7_unpad(plain)
    return parse_profile(plain.decode())


plain1 = "A" * 13
plain2 = "A" * 10 + "admin" + chr(11) * 11
cipher1 = encrypt_profile(profile_for(plain1))
cipher2 = encrypt_profile(profile_for(plain2))
assert(decrypt_profile(cipher1[:32] + cipher2[16:32])['role'] == "admin")
