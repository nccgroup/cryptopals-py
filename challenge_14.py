from os.path import commonprefix

from challenge_12 import *


def find_prefix_length(oracle: ECBOracleType, block_size: int) -> int:
    ct_1 = oracle(bytes(16))
    ct_2 = oracle(b'\x01')
    eq_blocks = len(commonprefix((ct_1, ct_2))) // block_size
    index = block_size * (eq_blocks + 1)
    for i in range(1, 17):
        ct_3 = oracle(bytes(i) + b'\x01')
        if ct_1[:index] == ct_3[:index]:
            return index - i
    raise Exception("oh no!")


def wrap_oracle(oracle: ECBOracleType, prefix_len: int, block_size: int) -> ECBOracleType:
    pad_len = block_size - (prefix_len % block_size)
    cutoff_ind = prefix_len + pad_len

    def wrapped_oracle(message: bytes) -> bytes:
        return oracle(bytes(pad_len) + message)[cutoff_ind:]
    return wrapped_oracle


if __name__ == "__main__":
    oracle = make_oracle()

    # step 1: determine the sizes of unknown data fields
    block_size, affix_len = find_block_size_and_postfix_length(oracle)
    print(f"{block_size=}")
    print(f"{affix_len=}")
    assert block_size == AES.block_size
    prefix_len = find_prefix_length(oracle, block_size)
    postfix_len = affix_len - prefix_len

    # wrap the oracle
    oracle = wrap_oracle(oracle, prefix_len, block_size)

    # same as challenge 12:
    pt = main(oracle, postfix_len)
    print("Done!")
    print("Contents of 'unknown-string':\n")
    print(pt.decode("ascii"))
