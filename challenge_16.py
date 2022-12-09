from os import urandom

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_09 import pkcs7, strip_pkcs7


BLOCK_SIZE = AES.block_size
KEY_SIZE = 32
_key = urandom(KEY_SIZE)
iv = urandom(AES.block_size)


def wrap_userdata(data: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon" 
    data = data.replace(b";", b"%3B").replace(b"=", b"%3D")
    wrapped = prefix + data + suffix
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7(wrapped))


def check_for_admin(data: bytes, quiet=True) -> bool:
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    plaintext = strip_pkcs7(cipher.decrypt(data))
    if not quiet:
        print(f"{plaintext=}")
    return b";admin=true;" in plaintext


def make_admin() -> bytes:
    a_block = b"A" * BLOCK_SIZE
    ct = wrap_userdata(a_block * 2)
    flipper = bytes_xor(a_block, b";admin=true".rjust(BLOCK_SIZE, b"A"))
    padded = flipper.rjust(BLOCK_SIZE*3, b"\x00").ljust(len(ct), b"\x00")
    new_ct = bytes_xor(ct, padded)
    return new_ct


if __name__ == "__main__":
    forged_ct = make_admin()
    print(f"{forged_ct=}")
    print("Admin check:", check_for_admin(forged_ct, quiet=False))
