from itertools import count
from base64 import b64decode
from typing import Callable
from os import urandom

from Crypto.Cipher import AES

from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7


BLOCK_SIZE = AES.block_size
KEY_SIZE = 32
ECBOracleType = Callable[[bytes], bytes]


def make_oracle() -> ECBOracleType:
    _key = urandom(KEY_SIZE)
    with open("data/12") as f:
        _secret_postfix = b64decode(f.read())

    def oracle(plaintext: bytes) -> bytes:
        plaintext = pkcs7(plaintext + _secret_postfix)
        cipher = AES.new(_key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)

    return oracle


def find_block_size_and_postfix_length(enc: ECBOracleType) -> tuple[int, int]:
    block_size = None
    postfix_len = None

    l = len(enc(b"A"))
    for i in count(2):
        l2 = len(enc(b"A" * i))
        if l2 > l:
            block_size = l2 - l
            postfix_len = l - i
            break

    assert block_size is not None
    assert postfix_len is not None
    return block_size, postfix_len


def detect_ecb(oracle):
    ct = oracle(bytes(32))
    if ct[:16] == ct[16:32]:
        return True
    raise Exception("oh no!")


def guess_byte(prefix: bytes, target: bytes, oracle: ECBOracleType) -> bytes:
    for b in range(256):
        b = bytes([b])
        msg = prefix + b
        first_block = oracle(msg)[:16]
        if first_block == target:
            return b
    raise Exception("oh no!")


def main(oracle: ECBOracleType, postfix_len: int, fancy=False) -> bytes:
    # step 2: detect that the oracle uses ECB
    assert detect_ecb(oracle)

    # submit messages to the oracle of lengths 15 to 0 (inclusive),
    # collect resulting ciphertexts, transpose them blockwise,
    # then flatten and truncate the result
    ciphertexts = [bytes_to_chunks(oracle(bytes(15-n)), BLOCK_SIZE) for n in range(16)]
    transposed = [block for blocks in zip(*ciphertexts) for block in blocks]
    blocks_to_attack = transposed[:postfix_len]

    # steps 3 through 6: recover the postfix byte-by-byte
    pt = bytes(15)
    for block in blocks_to_attack:
        pt += guess_byte(pt[-15:], block, oracle)
        if fancy:
            print(pt[15:])  # uncomment this to watch the decryption happen byte-by-byte
            from time import sleep
            sleep(0.1)
    return pt[15:]


if __name__ == "__main__":
    oracle = make_oracle()

    # step 1: determine the sizes of unknown data fields
    block_size, postfix_len = find_block_size_and_postfix_length(oracle)
    print(f"{block_size=}")
    print(f"{postfix_len=}")
    assert block_size == AES.block_size

    pt = main(oracle, postfix_len)

    print("Done!")
    print("Contents of 'unknown-string':\n")
    print(pt.decode("ascii"))
