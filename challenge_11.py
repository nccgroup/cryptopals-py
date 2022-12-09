from os import urandom
from random import choice, randint
from typing import Callable

from Crypto.Cipher import AES

from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7


EncOracleType = Callable[[bytes], bytes]  # takes one bytestring argument, returns bytes

BLOCK_SIZE = AES.block_size
KEY_SIZE = 32


def get_encryption_oracle() -> tuple[str, EncOracleType]:
    mode = choice(("ECB", "CBC"))

    def encryption_oracle(plaintext: bytes) -> bytes:
        key = urandom(KEY_SIZE)
        prefix = urandom(randint(5, 10))
        postfix = urandom(randint(5, 10))
        plaintext = pkcs7(prefix + plaintext + postfix)
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            iv = urandom(BLOCK_SIZE)
            cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)

    return mode, encryption_oracle


def detector(func: EncOracleType) -> str:
    plaintext = bytes(2*BLOCK_SIZE + (BLOCK_SIZE-5))
    ciphertext = func(plaintext)
    ct_blocks = bytes_to_chunks(ciphertext, BLOCK_SIZE)
    if ct_blocks[1] == ct_blocks[2]:
        return "ECB"
    else:
        return "CBC"


if __name__ == "__main__":
    for _ in range(1000):
        _mode, oracle = get_encryption_oracle()
        guess = detector(oracle)
        print("Actual:", _mode, "  Guessed:", guess)
        if _mode != guess:
            raise Exception("Oh no!")
    print("It worked!")
