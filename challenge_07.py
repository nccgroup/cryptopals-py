from base64 import b64decode

from Crypto.Cipher import AES


def aes_ecb_dec(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    with open("data/7.txt") as f:
        data_b64 = f.read()

    ciphertext = b64decode(data_b64)
    plaintext = aes_ecb_dec(b'YELLOW SUBMARINE', ciphertext)

    print(f"{plaintext=}")
