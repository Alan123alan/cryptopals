# import string
import base64

#when trying to convert a hex string to it's bytes representation
#you need to use bytes.fromhex()
#then you can easily encode those bytes to base64 with base64.b64encode()
def hex_2_base64(hex_str:str)->bytes:
    return base64.b64encode(bytes.fromhex(hex_str))

# when trying to convert a base64 string to it's bytes representation
# you can use .encode("utf-8") or bytes(b64_str, "utf-8")
# then you can easily decode those bytes from base64 with base64.b64decode()
def base64_decode(base64_str:bytes)->bytes:
    # return base64.b64decode(base64_str.encode(encoding="utf-8"))
    return base64.b64decode(base64_str)

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


def repeating_key_xor_encrypt(buffer, key):
    buffer_bytes = bytes(buffer, "utf-8")
    key_bytes = bytes(key, "utf-8")
    print("key bytes", key_bytes)
    encrypted_bytes = b""
    for i, buffer_byte in enumerate(buffer_bytes):
        print("i", i)
        print("buffer byte", buffer_byte)
        print("current key byte", key_bytes[i%len(key_bytes)])
        encrypted_bytes += bytes([key_bytes[i%len(key_bytes)] ^ buffer_byte])
    return encrypted_bytes


def hamming_distance(buffer_1, buffer_2):
    buffer_1_bytes = bytes(buffer_1, "utf-8")
    buffer_2_bytes = bytes(buffer_2, "utf-8")
    if len(buffer_1_bytes) != len(buffer_2_bytes):
        raise "Both buffers need to be the same length to calculate hamming distance"
    differing_bits_count = 0
    for b1_byte, b2_byte in zip(buffer_1_bytes, buffer_2_bytes):
        for i in range(32):
            # shift buffer bytes to the right (ints occupy 32 bits in memory)
            # bitwise and the buffer bytes with 1, this way we will compare only the current bit of interest 
            if ((b1_byte >> i) & 1) != ((b2_byte >> i) & 1):
                differing_bits_count += 1

    return differing_bits_count 


def repeating_key_xor_decrypt(buffer):
    pass


def highest_probability_decrypted_bytes(encrypted_str):
    highest_probability = -1
    highest_probability_key = -1
    highest_probability_decrypted_bytes = ""
    for key in range(128):
        decrypted_bytes = xor_decrypt(encrypted_str, key)
        # print(decrypted_bytes)
        # print(decrypted_bytes.decode(encoding="utf-8"))
        #setting all chars in the decoded string to lower breaks the algo
        current_probability = sum([frequencies.get(chr(decrypted_byte),0) for decrypted_byte in decrypted_bytes])
        if current_probability > highest_probability:
            highest_probability = current_probability
            highest_probability_key = key
            highest_probability_decrypted_bytes = decrypted_bytes
    return (highest_probability_key, highest_probability_decrypted_bytes)

# finding the single character key that XOR'd a message and getting the decrypted message
# highest_probability_key, highest_probability_decrypted_str = highest_probability_decrypted_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
# print(highest_probability_key)
# print(highest_probability_decrypted_str)


# getting the most probable decrypted version of each line in a file
# then selecting the line with highest probability of being plain english
# file = open("./single_xor_hay.txt")
# lines = [line.strip("\n") for line in file.readlines()]
# most_probable_decrypted_lines = []
# for line in lines:
#     print(line)
#     decryption_key, decrypted_bytes = highest_probability_decrypted_bytes(line)
#     most_probable_decrypted_lines.append(decrypted_bytes)
#     print(decryption_key)
#     print(decrypted_bytes)
# # print(lines)
# highest_probability = -1
# hidden_message = ""
# for decrypted_line in most_probable_decrypted_lines:
#         current_probability = sum([frequencies.get(chr(decrypted_byte),0) for decrypted_byte in decrypted_line])
#         if current_probability > highest_probability:
#             highest_probability = current_probability
#             hidden_message = decrypted_line

# print("hidden message", hidden_message)

# encrypting a message using repeating-key XOR algorithm
# encrypted_message = repeating_key_xor_encrypt("""Burning 'em, if you ain't quick and nimble
# I go crazy when I hear a cymbal""", "ICE")
# print(encrypted_message.hex())


# calculating hamming distance
# usually in coding challenges hamming distance is calculated by comparing and getting the count of differing chars between strings
# cryptopals defines it as the differing bits
# compare the bits in each byte? yes!
# print(hamming_distance("this is a test", "wokka wokka!!!"))

# a whole file was encrypted with repeating-key XOR then encrypted to base64
# to start breaking the repeating-key XOR we first need to undo the  data transformations post the repeating key XOR encryption
# repeating-key XOR -> base64 <- base64 <- repeating-key XOR
file = open("repeating_xor_encrypted_hay.txt")
b64_decoded_line_bytes = b""
for line in file.readlines():
    b64_decoded_line_bytes += base64.b64decode(line.strip("\n"))
# breaking the repeating-key XOR
# for each possible keysize take the first and second keysize worth of bytes
# and calculate the hamming distance
keysizes = list(range(2,40))
# calculating the hamming distance between two substrings of varying lengths from the encrypted file 
# let's us test for the repetition rate of the key, if key is size 4, every 4 bytes we are going to have the key repeating
# seems like this breaking algorithm is based on the XOR operation leaving some kind of trace on it's result
normalized_hamming_distances = []
for keysize in keysizes:
    normalized_hamming_distances.append({
        "keysize": keysize,
        "distance": hamming_distance(b64_decoded_line_bytes[:keysize].decode("utf-8"), b64_decoded_line_bytes[keysize:keysize*2].decode("utf-8"))/keysize
    })

print(sorted(normalized_hamming_distances, key=lambda x: x["distance"]))



