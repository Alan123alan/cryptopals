# import string

def xor(buffer1:str, buffer2:str)->bytes:
    if len(buffer1) != len(buffer2):
        raise "Error, buffers have different lengths"
    buffer1_bytes = bytes.fromhex(buffer1)
    buffer2_bytes = bytes.fromhex(buffer2) 
    return bytes([b1_byte ^ b2_byte for (b1_byte, b2_byte) in zip(buffer1_bytes, buffer2_bytes)])

def xor_decrypt(encrypted_str, key):
    #Prefer the approach of constructing a bytes string
    # decrypted_bytes = b""
    # for byte in bytes.fromhex(encrypted_str):
    #     decrypted_bytes += bytes([byte ^ key])
    # return decrypted_bytes
    return bytes([byte ^ key for byte in bytes.fromhex(encrypted_str)])


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
        decrypted_bytes = xor_decrypt(encrypted_str, key)
        print(decrypted_bytes)
        # print(decrypted_bytes.decode(encoding="utf-8"))
        #setting all chars in the decoded string to lower breaks the algo
        current_probability = sum([frequencies.get(chr(decrypted_byte),0) for decrypted_byte in decrypted_bytes])
        if current_probability > highest_probability:
            highest_probability = current_probability
            highest_probability_key = key
            highest_probability_decrypted_str = decrypted_bytes
    return (highest_probability_key, highest_probability_decrypted_str)


highest_probability_key, highest_probability_decrypted_str = highest_probability_decrypted_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
print(highest_probability_key)
print(highest_probability_decrypted_str)