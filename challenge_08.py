BLOCK_SIZE = 16


def bytes_to_chunks(b: bytes, chunk_size: int, quiet=True) -> list[bytes]:
    chunks = [b[ind:ind+chunk_size] for ind in range(0, len(b), chunk_size)]
    if not quiet:
        print(f"Chunked input with size {chunk_size}: {chunks}")
    return chunks


if __name__ == "__main__":
    with open("data/8.txt") as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f]

    for i, ciphertext in enumerate(ciphertexts):
        num_blocks = len(ciphertext) // BLOCK_SIZE
        num_uniq_blocks = len(set(bytes_to_chunks(ciphertext, BLOCK_SIZE)))
        repeated_blocks = num_blocks - num_uniq_blocks
        if repeated_blocks == 0:
            continue
        print(f"Line {i} has {repeated_blocks} repeated blocks and is likely using ECB")
