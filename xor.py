import string

def xor(buffer1:str, buffer2:str)->bytes:
    if len(buffer1) != len(buffer2):
        raise "Error, buffers have different lengths"
    buffer1_bytes = bytes.fromhex(buffer1)
    buffer2_bytes = bytes.fromhex(buffer2) 
    return bytes([b1_byte ^ b2_byte for (b1_byte, b2_byte) in zip(buffer1_bytes, buffer2_bytes)])

def xor_decrypt(encrypted_str, key):
    # Ensure key is an integer
    key = ord(key) if isinstance(key, str) else key
    # XOR operation for each byte
    return bytes(byte ^ key for byte in bytes.fromhex(encrypted_str))


def highest_probability_decrypted_str(encrypted_str):
    frequencies = {
        "e" : 12000,
        "t" : 9000,
        "a" : 8000,
        "i" : 8000,
        "n" : 8000,
        "o" : 8000,
        "s" : 8000,
        "h" : 6400,
        "r" : 6200,
        "d" : 4400,
        "l" : 4000,
        "u" : 3400,
        "c" : 3000,
        "m" : 3000,
        "f" : 2500,
        "w" : 2000,
        "y" : 2000,
        "g" : 1700,
        "p" : 1700,
        "b" : 1600,
        "v" : 1200,
        "k" : 800,
        "q" : 500,
        "j" : 400,
        "x" : 400,
        "z" : 200,
    }
    highest_probability = -1
    highest_probability_key = -1
    highest_probability_decrypted_str = ""
    for key in range(128):
        print(f"do you loop? {key}")
        decrypted_str = xor_decrypt(encrypted_str, key).decode(encoding="utf-8")
        if sum([frequencies.get(ch,0) for ch in decrypted_str]) > highest_probability:
            highest_probability = sum([frequencies.get(ch.lower(),0) for ch in decrypted_str])
            highest_probability_key = key
            highest_probability_decrypted_str = decrypted_str
    return (highest_probability_key, highest_probability_decrypted_str)


highest_probability_key, highest_probability_decrypted_str = highest_probability_decrypted_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
print(highest_probability_key)
print(highest_probability_decrypted_str)