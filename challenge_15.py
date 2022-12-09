from challenge_09 import strip_pkcs7, PaddingError


def test_invalid_padding(bs: bytes):
    try:
        strip_pkcs7(bs)
    except PaddingError:
        return
    raise Exception("oh no!")


if __name__ == "__main__":
    if strip_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") != b"ICE ICE BABY":
        raise Exception("oh no!")

    test_invalid_padding(b"ICE ICE BABY\x05\x05\x05\x05")
    test_invalid_padding(b"ICE ICE BABY\x01\x02\x03\x04")

    print("Tests passed.")
