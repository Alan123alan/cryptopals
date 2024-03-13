import base64
import sys
from challenge_3 import english_score, break_single_key_xor_encryption
from challenge_5 import repeating_key_xor


def b_hamming_distance(buffer_a_bytes, buffer_b_bytes):
    if len(buffer_a_bytes) != len(buffer_b_bytes):
        raise "Both buffers need to be the same length to calculate hamming distance"
    differing_bits_count = 0
    for b1_byte, b2_byte in zip(buffer_a_bytes, buffer_b_bytes):
        for i in range(32):
            # shift buffer bytes to the right (ints occupy 32 bits in memory)
            # bitwise and the buffer bytes with 1, this way we will compare only the current bit of interest 
            if ((b1_byte >> i) & 1) != ((b2_byte >> i) & 1):
                differing_bits_count += 1

    return differing_bits_count 


def break_repeating_key_xor(repeating_key_xor_encrypted_bytes):
    # breaking the repeating-key XOR
    # guess_keysize = sys.maxsize
    # lowest_normalized_hamming_distance = sys.maxsize
    # for keysize in range(2,40):
    #     if keysize*2 > len(repeating_key_xor_encrypted_bytes):
    #         break
    #     first_keysize_block = repeating_key_xor_encrypted_bytes[:keysize]
    #     second_keysize_block = repeating_key_xor_encrypted_bytes[keysize:keysize*2]
    #     print(f"first keysize block {first_keysize_block} with length {len(first_keysize_block)}, second keysize block {second_keysize_block} with length {len(second_keysize_block)}")
    #     normalized_hamming_distance = b_hamming_distance(first_keysize_block, second_keysize_block)/(8*keysize) 
    #     if normalized_hamming_distance < lowest_normalized_hamming_distance:
    #         lowest_normalized_hamming_distance = normalized_hamming_distance
    #         guess_keysize = keysize
    #is keysize the issue 
    guess_keysize = 3
    print("Guess keysize: ", guess_keysize)

    #break the cipher into blocks of keysize length
    #calculate the number of full keysize length blocks of bytes in the file
    keysize_blocks_count = len(repeating_key_xor_encrypted_bytes) // guess_keysize
    print("Number of keysize blocks in file bytes computed: ", keysize_blocks_count)
    #calculate the remainder number of bytes that don't fit into a full keysize block
    remainder_bytes_count = len(repeating_key_xor_encrypted_bytes) % guess_keysize
    print("Number of remaining bytes computed: ", remainder_bytes_count)
    keysize_blocks = [repeating_key_xor_encrypted_bytes[i*guess_keysize:(i+1)*guess_keysize] for i in range(keysize_blocks_count)]

    print(f"keysize blocks {keysize_blocks}")
    #break the continous keysize blocks into key specific blocks
    key_blocks = []
    for i in range(guess_keysize):
        key_block = b""
        for keysize_block in keysize_blocks:
            # print(keysize_block[i], type(keysize_block[i]))
            # print(keysize_block[i].to_bytes(1, byteorder="big"), type(keysize_block[i]))
            key_block += keysize_block[i].to_bytes(1, byteorder="big")
            # per_keysize_block.append(keysize_block[i])
        key_blocks.append(key_block)

    print(f"Blocks: {key_blocks}")

    # (TO BE IMPLEMENTED) append the remaining bytes into the corresponding groups
    # after decrypting some encrypted bytes, this function calculates a score of the probability the decrypted bytes are english
    #correct results are appearing as the fourth lowest scored, need to fix the english scoring function
    highest_probability_keys = []
    for key_block in key_blocks:
        # finding the single character key that XOR'd a message and getting the decrypted message
        result = break_single_key_xor_encryption(key_block, list(range(256)))
        print(f"Result : {result}")

    print(highest_probability_keys)
    # return b_repeating_key_xor_encrypt(repeating_key_xor_encrypted_bytes, highest_probability_keys)





#TESTS
#checking that b_repeating_key_xor can encrypt all ascii (0-256) chars from a message
#base64 encrypt the result of the b_repeating_key_xor
#decrypt the base64 and b_repeating_key_xor and get back the same messahe
def test_break_repeating_key_xor():
    # file = open("../repeating_xor_encrypted_hay.txt")
    # b64_decoded_file_bytes = b""
    # for line in file.readlines():
    #     # print("striped decoded line", base64.b64decode(bytes(line.strip(), "ascii")).decode("utf-8"))
    #     b64_decoded_file_bytes += base64.b64decode(bytes(line.strip(), "ascii"))
    # # b64_decoded_file_bytes_length = len(b64_decoded_file_bytes)
    # break_repeating_key_xor(b64_decoded_file_bytes)
    cipher = """Hellohellohello"""
    key = "scr"#115 99 114
    repeating_key_xor_encrypted_cipher = repeating_key_xor(bytes(cipher, "utf-8"), bytes(key, "utf-8"))
    print("repeating-key xor encrypted bytes: ",repeating_key_xor_encrypted_cipher)
    b64_repeating_key_xor_encrypted_cipher = base64.b64encode(repeating_key_xor_encrypted_cipher)
    print("base64 encoded repeating-key xor enconded bytes: " ,b64_repeating_key_xor_encrypted_cipher)
    repeating_key_xor_encrypted_cipher = base64.b64decode(b64_repeating_key_xor_encrypted_cipher)
    print("repeating-key xor encrypted bytes after decoding from base64: ",repeating_key_xor_encrypted_cipher)
    print("Decrypted message: ", repeating_key_xor(repeating_key_xor_encrypted_cipher, bytes(key, "utf-8")).decode("utf-8"))
    print(break_repeating_key_xor(repeating_key_xor_encrypted_cipher))





if __name__ == "__main__":
    test_break_repeating_key_xor()