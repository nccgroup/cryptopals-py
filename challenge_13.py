from Crypto.Cipher import AES

from os import urandom

from challenge_09 import pkcs7, strip_pkcs7


KEY_SIZE = 32
_key = urandom(KEY_SIZE)


def profile_parse(profile: bytes) -> dict[bytes, bytes]:
    kv_pairs = profile.split(b"&")
    parsed = {
        key: value for key, value in [pair.split(b"=") for pair in kv_pairs]
    }
    return parsed


def profile_build(t: tuple[tuple[bytes, bytes], ...]) -> bytes:
    result = b'&'.join(key + b'=' + val for key, val in t)
    return result


def profile_for(email: bytes) -> bytes:
    # note: I'm opting not to do any email validation beyond rejecting profile
    # metacharacters here (so like, no RFC 5322 stuff)

    email = email.translate(None, b'&=')  # remove & and = characters
    result = profile_build((
        (b'email', email),
        (b'uid', b'10'),
        (b'role', b'user')
        ))
    return result


def enc_profile(email: bytes) -> bytes:
    cipher = AES.new(_key, AES.MODE_ECB)
    profile = profile_for(email)
    return cipher.encrypt(pkcs7(profile))


def dec_profile(encrypted: bytes) -> bytes:
    cipher = AES.new(_key, AES.MODE_ECB)
    plaintext = strip_pkcs7(cipher.decrypt(encrypted))
    return plaintext


def do_evil() -> bytes:
    # generate a ciphertext for an admin profile
    user_1 = b'foooo@bar.com'
    user_2 = user_1[:10] + pkcs7(b'admin') + user_1[10:]  # include parts of user_1 so it looks at least a _little_ like an email
    print(f"{user_1=}\n{user_2=}")
    ct_1 = enc_profile(user_1)
    ct_2 = enc_profile(user_2)
    return ct_1[:32] + ct_2[16:32]


if __name__ == "__main__":
    evil = do_evil()
    print("Malicious ciphertext:", evil)
    print("Decryption:", dec_profile(evil))
    profile = dec_profile(evil)
