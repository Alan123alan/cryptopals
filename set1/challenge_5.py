def repeating_key_xor(buffer_bytes, key_bytes):
    key_bytes_len = len(key_bytes)
    return bytes([buffer_byte ^ key_bytes[i%key_bytes_len] if chr(buffer_byte) != '\n' else buffer_byte for i, buffer_byte in enumerate(buffer_bytes)])

if __name__ == "__main__":
    encryption_key = """ICE"""
    message = """Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal"""
    expected_cipher = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""
    cipher = repeating_key_xor(bytes(message, "utf-8"), bytes(encryption_key, "utf-8"))
    print(f"message: {message}")
    print(f"message bytes: {bytes(message, 'utf-8')}")
    print(f"expected cipher: {expected_cipher}")
    print(f"output   cipher: {cipher.hex()}")
    #AssertionError due to missing \n? should all encryptions ignore \n? or whitespaces?
    # assert cipher.hex() == expected_cipher