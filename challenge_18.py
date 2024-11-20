from base64 import b64decode
from Crypto.Cipher import AES
from struct import pack


CIPHERTEXT = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
KEY = b"YELLOW SUBMARINE"
nonce = 0


def _keystream(key: bytes, nonce: int):
    cipher = AES.new(key, AES.MODE_ECB)
    count = 0
    cap = 2**64
    while True:
        pt_block = pack("QQ", nonce, count)
        key_block = cipher.encrypt(pt_block)
        yield from key_block
        count += 1
        assert count < cap


def aes_ctr_enc(key: bytes, plaintext: bytes, nonce: int = 0) -> bytes:
    return bytes(pt ^ ks for pt, ks in zip(plaintext, _keystream(key, nonce)))


aes_ctr_dec = aes_ctr_enc


if __name__ == "__main__":
    plaintext = aes_ctr_dec(KEY, CIPHERTEXT)
    print("Plaintext:", plaintext)
