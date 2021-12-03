from base64 import b16decode, b64encode


def hex_to_b64(data_hex: bytes) -> bytes:
    return b64encode(b16decode(data_hex, casefold=True))


if __name__ == "__main__":
    data_hex = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    data_b64 = hex_to_b64(data_hex)

    print(f"{data_hex=}")
    print(f"{data_b64=}")

    if data_b64 == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t":
        print("It worked!")
    else:
        exit("Conversion failed (this should never happen!)")
