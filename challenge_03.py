from dataclasses import dataclass, astuple
from typing import Optional

from challenge_02 import bytes_xor


frequencies = {
    "a": 0.07743208627550165,
    "b": 0.01402241586697527,
    "c": 0.02665670667329359,
    "d": 0.04920785702311875,
    "e": 0.13464518994079883,
    "f": 0.025036247121552113,
    "g": 0.017007472935972733,
    "h": 0.05719839895067157,
    "i": 0.06294794236928244,
    "j": 0.001267546400727001,
    "k": 0.005084890317533608,
    "l": 0.03706176274237046,
    "m": 0.030277007414117114,
    "n": 0.07125316518982316,
    "o": 0.07380002176297765,
    "p": 0.017513315119093483,
    "q": 0.0009499245648139707,
    "r": 0.06107162078305546,
    "s": 0.061262782073188304,
    "t": 0.08760480785349399,
    "u": 0.030426995503298266,
    "v": 0.01113735085743191,
    "w": 0.02168063124398945,
    "x": 0.0019880774173815607,
    "y": 0.022836421813561863,
    "z": 0.0006293617859758195,
}


@dataclass(order=True)
class ScoredGuess:
    score: float = float("inf")
    key: Optional[int] = None  # int value of repeated byte used as key
    ciphertext: Optional[bytes] = None
    plaintext: Optional[bytes] = None

    @classmethod
    def from_key(cls, ct, key_val):
        full_key = bytes([key_val]) * len(ct)
        pt = bytes_xor(ct, full_key)
        score = score_text(pt)
        return cls(score, key_val, ct, pt)


def score_text(text: bytes) -> float:
    # lower scores are better
    score = 0.0
    l = len(text)

    for letter, frequency_expected in frequencies.items():
        frequency_actual = text.count(ord(letter)) / l
        err = abs(frequency_expected - frequency_actual)
        score += err

    return score


def crack_xor_cipher_simple(ciphertext: bytes) -> ScoredGuess:
    best_guess = ScoredGuess()

    for candidate_key in range(256):
        guess = ScoredGuess.from_key(ciphertext, candidate_key)
        best_guess = min(best_guess, guess)  # compares guesses by score, because we passed order=True to the dataclass decorator

    if best_guess.key is None or best_guess.plaintext is None:
        exit("no key found (this should never happen!)")
    return best_guess


def crack_xor_cipher(ct: bytes) -> ScoredGuess:
    best_guess = ScoredGuess()

    ct_len = len(ct)
    ct_freqs = {b: ct.count(b) / ct_len for b in range(256)}

    for candidate_key in range(256):
        score = 0
        for letter, frequency_expected in frequencies.items():
            score += abs(frequency_expected - ct_freqs[ord(letter) ^ candidate_key])
        guess = ScoredGuess(score, candidate_key)
        best_guess = min(best_guess, guess)

    if best_guess.key is None:
        exit("no key found (this should never happen!)")
    best_guess.ciphertext = ct
    best_guess.plaintext = bytes_xor(ct, bytes([best_guess.key]) * len(ct))

    return best_guess


if __name__ == "__main__":
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    best_guess = crack_xor_cipher(ciphertext)
    score, key, ciphertext, plaintext = astuple(best_guess)
    print(f"{key=}")
    print(f"{plaintext=}")
