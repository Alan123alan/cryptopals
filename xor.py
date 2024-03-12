# import string
import base64
import sys

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

#Morse frequencies, it works intermittently
# frequencies = { "e" : 12000,"t" : 9000,"i" : 8000,"a" : 8000,"n" : 8000,"o" : 8000,"s" : 8000,"h" : 6400,"r" : 6200,"d" : 4400,"l" : 4000,"u" : 3400,"c" : 3000,"m" : 3000,"f" : 2500,"w" : 2000,"y" : 2000,"g" : 1700,"p" : 1700,"b" : 1600,"v" : 1200,"k" : 800,"q" : 500,"j" : 400,"x" : 400,"z" : 200}


#frequencies taken from wikipedia letter frequency
#https://en.wikipedia.org/wiki/Letter_frequency
frequencies = {"e" : 12.7,"t" : 9.1,"a" : 8.2,"i" : 7.0,"n" : 6.7,"o" : 7.5,"s" : 6.3,"h" : 6.1,"r" : 6.0,"d" : 4.3,"l" : 4.0,"u" : 2.8,"c" : 2.8,"m" : 2.4,"f" : 2.2,"w" : 2.4,"y" : 2.0,"g" : 2.0,"p" : 1.9,"b" : 1.5,"v" : 0.98,"k" : 0.77,"q" : 0.095,"j" : 0.15,"x" : 0.15,"z" : 0.074}


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

def b_xor_decrypt(encrypted_bytes, key):
    #Prefer the approach of constructing a bytes string
    decrypted_bytes = b""
    for byte in encrypted_bytes:
        decrypted_bytes += (byte ^ key).to_bytes(1, byteorder="big")
    return decrypted_bytes
    # return [byte ^ key for byte in bytes]


def repeating_key_xor_encrypt(buffer, key):
    buffer_bytes = bytes(buffer, "utf-8")
    key_bytes = bytes(key, "utf-8")
    # print("key bytes", key_bytes)
    encrypted_bytes = b""
    for i, buffer_byte in enumerate(buffer_bytes):
        # print("i", i)
        # print("buffer byte", buffer_byte)
        # print("current key byte", key_bytes[i%len(key_bytes)])
        encrypted_bytes += bytes([key_bytes[i%len(key_bytes)] ^ buffer_byte])
    return encrypted_bytes

def b_repeating_key_xor_encrypt(buffer_bytes, key_bytes):
    encrypted_bytes = b""
    for i, buffer_byte in enumerate(buffer_bytes):
        # print("i", i)
        # print("buffer byte", buffer_byte)
        # print("current key byte", key_bytes[i%len(key_bytes)])
        encrypted_bytes += bytes([key_bytes[i%len(key_bytes)] ^ buffer_byte])
    return encrypted_bytes

def hamming_distance(buffer_1, buffer_2):
    buffer_1_bytes = bytes(buffer_1, "utf-8")
    buffer_2_bytes = bytes(buffer_2, "utf-8")
    if len(buffer_1_bytes) != len(buffer_2_bytes):
        raise "Both buffers need to be the same length to calculate hamming distance"
    differing_bits_count = 0
    for b1_byte, b2_byte in zip(buffer_1_bytes, buffer_2_bytes):
        for i in range(8):
            # shift buffer bytes to the right (ints occupy 32 bits in memory)
            # bitwise and the buffer bytes with 1, this way we will compare only the current bit of interest 
            if ((b1_byte >> i) & 1) != ((b2_byte >> i) & 1):
                differing_bits_count += 1

    return differing_bits_count 

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


def repeating_key_xor_decrypt(buffer):
    pass


def highest_probability_decrypted_bytes(encrypted_str):
    highest_probability = -1
    highest_probability_key = -1
    highest_probability_decrypted_bytes = ""
    for key in range(256):
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
# highest_probability_key, highest_probability_decrypted_str = b_highest_probability_decrypted_bytes(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
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


def guess_repeating_key_xor_keysize(repeating_key_xor_encrypted_bytes):
    # for each possible keysize take the first and second keysize worth of bytes
    # and calculate the hamming distance per bit
    # calculating the hamming distance between two substrings of varying lengths from the encrypted file 
    # let's us test for the repetition rate of the key, if key is size 4, every 4 bytes we are going to have the key repeating
    # seems like this breaking algorithm is based on the XOR operation leaving some kind of trace on it's result
    # try by normalizing the sum of all bit differences by dividing over the keysize, getting the avg differences per byte
    guess_keysize = sys.maxsize
    lowest_normalized_hamming_distance = sys.maxsize
    # limit_keysize = 40 if len(repeating_key_xor_encrypted_bytes) >= 40 else len(repeating_key_xor_encrypted_bytes)
    for keysize in range(2, 41):
        score = 0
        n = 0
        for offset in range(len(repeating_key_xor_encrypted_bytes)-1):
            #if we have reached a keysize in which the second keysize block is out of bounds of repeating_key_xor_encrypted_bytes
            #break out of the loop and return the current guess size
            if keysize*2 > len(repeating_key_xor_encrypted_bytes):
                return guess_keysize
            first_keysize_block_start = (offset*keysize) 
            first_keysize_block_end = (offset*keysize)+keysize 
            second_keysize_block_start = (offset*keysize)+keysize 
            second_keysize_block_end = (offset*keysize)+(2*keysize) 
            if second_keysize_block_end > len(repeating_key_xor_encrypted_bytes):
                break
            first_keysize_block = repeating_key_xor_encrypted_bytes[first_keysize_block_start:first_keysize_block_end]
            second_keysize_block = repeating_key_xor_encrypted_bytes[second_keysize_block_start:second_keysize_block_end] 
            # print(f"first keysize block {first_keysize_block} with length {len(first_keysize_block)}, second keysize block {second_keysize_block} with length {len(second_keysize_block)}")
            score += b_hamming_distance(first_keysize_block, second_keysize_block)/(8*keysize)
            n += 1
        normalized_hamming_distance = score / n
        # print(f"current keysize: {keysize} and current normalized hamming distance: {normalized_hamming_distance}")
        if normalized_hamming_distance < lowest_normalized_hamming_distance:
            lowest_normalized_hamming_distance = normalized_hamming_distance
            guess_keysize = keysize
    return guess_keysize

def break_repeating_key_xor(repeating_key_xor_encrypted_bytes):
    # breaking the repeating-key XOR
    guess_keysize = sys.maxsize
    lowest_normalized_hamming_distance = sys.maxsize
    for keysize in range(2,40):
        if keysize*2 > len(repeating_key_xor_encrypted_bytes):
            break
        first_keysize_block = repeating_key_xor_encrypted_bytes[:keysize]
        second_keysize_block = repeating_key_xor_encrypted_bytes[keysize:keysize*2]
        print(f"first keysize block {first_keysize_block} with length {len(first_keysize_block)}, second keysize block {second_keysize_block} with length {len(second_keysize_block)}")
        normalized_hamming_distance = b_hamming_distance(first_keysize_block, second_keysize_block)/(8*keysize) 
        if normalized_hamming_distance < lowest_normalized_hamming_distance:
            lowest_normalized_hamming_distance = normalized_hamming_distance
            guess_keysize = keysize
        
    print("Guess keysize: ", guess_keysize)

    #break the cipher into blocks of keysize length
    #calculate the number of full keysize length blocks of bytes in the file
    keysize_blocks_count = len(repeating_key_xor_encrypted_bytes) // guess_keysize
    print("Number of keysize blocks in file bytes computed: ", keysize_blocks_count)
    #calculate the remainder number of bytes that don't fit into a full keysize block
    remainder_bytes_count = len(repeating_key_xor_encrypted_bytes) % guess_keysize
    print("Number of remaining bytes computed: ", remainder_bytes_count)
    keysize_blocks = [repeating_key_xor_encrypted_bytes[i*guess_keysize:(i+1)*guess_keysize] for i in range(keysize_blocks_count-1)]

    #break the continous keysize blocks into key specific blocks
    per_keysize_blocks = []
    for i in range(guess_keysize):
        per_keysize_block = b""
        for keysize_block in keysize_blocks:
            # print(keysize_block[i], type(keysize_block[i]))
            # print(keysize_block[i].to_bytes(1, byteorder="big"), type(keysize_block[i]))
            per_keysize_block += keysize_block[i].to_bytes(1, byteorder="big")
            # per_keysize_block.append(keysize_block[i])
        per_keysize_blocks.append(per_keysize_block)

    print(f"previous to remainder bytes insertion\nBlock: {per_keysize_blocks[0].decode('utf-8')}\nBlock length: {len(per_keysize_blocks[0])}")

    # (TO BE IMPLEMENTED) append the remaining bytes into the corresponding groups
    # #after decrypting some encrypted bytes, this function calculates a score of the probability the decrypted bytes are english
    def get_english_score(buffer_bytes:bytes):
        score = 0
        readable_message = buffer_bytes.decode("utf-8").strip()
        # print(f"readable message:{readable_message}")
        #create dictionary with frequencies of chars in readable_message excluding some special chars and whitespace chars
        char_frequencies = {}
        ignored_char_count = 0
        for c in readable_message.lower():
            if c in frequencies.keys():
                char_frequencies[c] = char_frequencies.get(c, 1)
            else:
                ignored_char_count += 1
        # print(f"char frequencies: {char_frequencies}")
        for c in char_frequencies.keys():
            #100% == len(message)
            #?%  == # occurences of <char>
            #message % covered by the occurences of a <char>
            char_frequency = char_frequencies[c]
            expected_char_frequency = (frequencies[c]/100)*(len(readable_message)-ignored_char_count)
            score += (char_frequency - expected_char_frequency)**2/expected_char_frequency
            # if c in frequencies.keys():
                #using chi-squared test
        # print(f"Readable message: \n{readable_message}\nChar frequencies: \n{char_frequencies}\nScore:\n{score}\n")
        #the lowest the score of some readable message it means the higher the likelihood that it's an english message
        return sys.maxsize if score == 0 else score


    def b_highest_probability_decrypted_bytes(encrypted_bytes):
        results = {}
        for key in range(256):
            decrypted_bytes = b_xor_decrypt(encrypted_bytes, key).decode("utf-8").strip()
            # print(f"current key {key} for decrypted block: {decrypted_bytes.decode('utf-8')} with english score: {get_english_score(decrypted_bytes)}")
            # current_probability = sum([frequencies.get(chr(decrypted_byte).lower(),0) for decrypted_byte in decrypted_bytes])
            current_probability_score = get_english_score(decrypted_bytes)
            results[key] = (decrypted_bytes.decode("utf-8"), current_probability_score)
        return 

    highest_probability_keys = []
    for key_block in per_keysize_blocks:
        # finding the single character key that XOR'd a message and getting the decrypted message
        highest_probability_key, highest_probability_decrypted_b = b_highest_probability_decrypted_bytes(key_block)
        highest_probability_keys.append(highest_probability_key)
        print(highest_probability_key.to_bytes(1, byteorder="big").decode("utf-8"))
        print(highest_probability_decrypted_b, type(highest_probability_decrypted_b))

    print(highest_probability_keys)
    return b_repeating_key_xor_encrypt(repeating_key_xor_encrypted_bytes, highest_probability_keys)





#TESTS
#checking that b_repeating_key_xor can encrypt all ascii (0-256) chars from a message
#base64 encrypt the result of the b_repeating_key_xor
#decrypt the base64 and b_repeating_key_xor and get back the same messahe
def test_break_repeating_key_xor():
    # file = open("repeating_xor_encrypted_hay.txt")
    # b64_decoded_file_bytes = b""
    # for line in file.readlines():
    #     # print("striped decoded line", base64.b64decode(bytes(line.strip(), "ascii")).decode("utf-8"))
    #     b64_decoded_file_bytes += base64.b64decode(bytes(line.strip(), "ascii"))
    # b64_decoded_file_bytes_length = len(b64_decoded_file_bytes)
    cipher = """Hello hello"""
    key = "sec"
    repeating_key_xor_encrypted_cipher = b_repeating_key_xor_encrypt(bytes(cipher, "utf-8"), bytes(key, "utf-8"))
    print("repeating-key xor encrypted bytes: ",repeating_key_xor_encrypted_cipher)
    b64_repeating_key_xor_encrypted_cipher = base64.b64encode(repeating_key_xor_encrypted_cipher)
    print("base64 encoded repeating-key xor enconded bytes: " ,b64_repeating_key_xor_encrypted_cipher)
    repeating_key_xor_encrypted_cipher = base64.b64decode(b64_repeating_key_xor_encrypted_cipher)
    print("repeating-key xor encrypted bytes after decoding from base64: ",repeating_key_xor_encrypted_cipher)
    print("Decrypted message: ", repeating_key_xor_encrypt(repeating_key_xor_encrypted_cipher.decode("utf-8"), key).decode("utf-8"))
    print(break_repeating_key_xor(repeating_key_xor_encrypted_cipher))
    





if __name__ == "__main__":
    test_break_repeating_key_xor()