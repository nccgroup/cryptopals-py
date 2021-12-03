from itertools import cycle, islice

from challenge_02 import bytes_xor


def repeating_key_xor(key: bytes, plaintext: bytes) -> bytes:
    full_key = bytes(islice(cycle(key), len(plaintext)))
    return bytes_xor(full_key, plaintext)


if __name__ == "__main__":
    plaintext = (b"Burning 'em, if you ain't quick and nimble\n"
                 b"I go crazy when I hear a cymbal")
    ct_expected = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    ciphertext = repeating_key_xor(b"ICE", plaintext)

    print(f"{ciphertext.hex()=}")

    if ciphertext == ct_expected:
        print("It worked!")
    else:
        exit("repeating-key xor didn't work (this should never happen!)")
