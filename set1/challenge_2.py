def xor(buffer_a_bytes, buffer_b_bytes):
    return bytes([buffer_a_byte ^ buffer_b_byte for buffer_a_byte, buffer_b_byte in zip(buffer_a_bytes, buffer_b_bytes)])


if __name__ == "__main__":
    cipher = "1c0111001f010100061a024b53535009181c"
    bytes_from_cipher = bytes.fromhex(cipher)
    print(xor(bytes_from_cipher, bytes.fromhex("686974207468652062756c6c277320657965")).decode("utf-8"))


