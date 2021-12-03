from challenge_03 import crack_xor_cipher, ScoredGuess


if __name__ == "__main__":
    with open("data/4.txt") as f:
        lines = [bytes.fromhex(line.strip()) for line in f]

    overall_best = ScoredGuess()
    for line in lines:
        print(end=".", flush=True)
        candidate = crack_xor_cipher(line)
        overall_best = min(overall_best, candidate)

    if overall_best.ciphertext is None:
        exit("no ciphertext found (this should never happen!)")

    print()
    print(f"{lines.index(overall_best.ciphertext)=}")
    print(f"{overall_best.key=}")
    print(f"{overall_best.plaintext=}")
