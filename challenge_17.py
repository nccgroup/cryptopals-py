from os import urandom
from base64 import b64decode
from random import choice
from typing import Optional
from sys import argv

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7, strip_pkcs7, PaddingError


BLOCK_SIZE = 16


_key = urandom(16)
iv = urandom(BLOCK_SIZE)


strings = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


def enc(ind: Optional[int] = None) -> bytes:
    s = choice(strings) if ind is None else strings[ind]
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7(s))
    return ciphertext


def _dec(iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def padding_oracle(iv: bytes, ciphertext: bytes) -> bool:
    plaintext = _dec(iv, ciphertext)
    try:
        strip_pkcs7(plaintext)
    except PaddingError:
        return False
    return True


def single_block_attack(iv: bytes, block: bytes, oracle) -> bytes:
    plaintext = b''
    zeroing_iv = [0]*BLOCK_SIZE

    for pad_len in range(1, BLOCK_SIZE+1):
        padding_iv = [pad_len ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_len] = candidate
            new_iv = bytes(padding_iv)
            if oracle(new_iv, block):
                if pad_len == 1:
                    # extra check required to confirm padding has length 1
                    padding_iv[-2] ^= 1
                    new_iv = bytes(padding_iv)
                    if not oracle(new_iv, block):
                        continue
                plaintext = bytes([candidate ^ pad_len]) + plaintext
                break
        else:
            raise Exception(f"No match found for byte {pad_len}")

        zeroing_iv[-pad_len] = candidate ^ pad_len

    return bytes_xor(plaintext, iv)


def padding_oracle_attack(ciphertext: bytes, oracle) -> bytes:
    plaintext = b''
    block_iv = iv
    blocks = bytes_to_chunks(ciphertext, BLOCK_SIZE)
    for i, block in enumerate(blocks):
        plaintext += single_block_attack(block_iv, block, oracle)
        block_iv = block
    return strip_pkcs7(plaintext)


if __name__ == "__main__":
    if len(argv) > 1 and "-a" in argv:
        # decrypt ciphertexts in order
        for i in range(len(strings)):
            ciphertext = enc(i)
            plaintext = padding_oracle_attack(ciphertext, padding_oracle)
            assert plaintext == strings[i]
            print(b64decode(plaintext).decode("ascii"))
    else:
        # choose a random "token"
        ciphertext = enc()
        plaintext = padding_oracle_attack(ciphertext, padding_oracle)
        print(plaintext)
