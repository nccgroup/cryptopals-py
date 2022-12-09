from base64 import b64decode

from challenge_02 import bytes_xor
from challenge_07 import aes_ecb_dec, AES
from challenge_08 import bytes_to_chunks
from challenge_09 import strip_pkcs7


BLOCK_SIZE = AES.block_size


def aes_cbc_dec(iv: bytes, key: bytes, ciphertext: bytes, use_pkcs7=True) -> bytes:
    blocks = bytes_to_chunks(ciphertext, BLOCK_SIZE)
    prev_ct = iv
    plaintext = b""
    for block in blocks:
        raw_dec = aes_ecb_dec(key, block)
        plaintext += bytes_xor(raw_dec, prev_ct)
        prev_ct = block
    if use_pkcs7:
        plaintext = strip_pkcs7(plaintext)
    return plaintext


if __name__ == "__main__":
    with open("data/10.txt") as f:
        data_b64 = f.read()
    ciphertext = b64decode(data_b64)

    key = b'YELLOW SUBMARINE'
    iv = bytes(BLOCK_SIZE)
    plaintext = aes_cbc_dec(iv, key, ciphertext)

    print(plaintext.decode("ascii"))
