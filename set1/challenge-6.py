import base64
import sys
import string

#frequencies taken from wikipedia letter frequency
#https://en.wikipedia.org/wiki/Letter_frequency
#passed values from percent to decimals
frequencies = {"e" : 0.127,"t" : 0.091,"a" : 0.082,"i" : 0.070,"n" : 0.067,"o" : 0.075,"s" : 0.063,"h" : 0.061,"r" : 0.060,"d" : 0.043,"l" : 0.040,"u" : 0.028,"c" : 0.028,"m" : 0.024,"f" : 0.022,"w" : 0.024,"y" : 0.020,"g" : 0.020,"p" : 0.019,"b" : 0.015,"v" : 0.0098,"k" : 0.0077,"q" : 0.00095,"j" : 0.0015,"x" : 0.0015,"z" : 0.00074}


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

def b_xor_decrypt(encrypted_bytes, key):
    #Prefer the approach of constructing a bytes string
    decrypted_bytes = b""
    for byte in encrypted_bytes:
        decrypted_bytes += (byte ^ key).to_bytes(1, byteorder="big")
    return decrypted_bytes
    # return [byte ^ key for byte in bytes]

def xor_decrypt(encrypted_str, key_byte):
    #Prefer the approach of constructing a bytes string
    # decrypted_bytes = b""
    # for byte in bytes.fromhex(encrypted_str):
    #     decrypted_bytes += bytes([byte ^ key])
    # return decrypted_bytes
    return bytes([byte ^ key_byte for byte in bytes(encrypted_str, "utf-8")])

def b_repeating_key_xor_encrypt(buffer_bytes, key_bytes):
    encrypted_bytes = b""
    for i, buffer_byte in enumerate(buffer_bytes):
        # print("i", i)
        # print("buffer byte", buffer_byte)
        # print("current key byte", key_bytes[i%len(key_bytes)])
        encrypted_bytes += bytes([key_bytes[i%len(key_bytes)] ^ buffer_byte])
    return encrypted_bytes


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
    for key_block in key_blocks:
        print(f"block lengths {len(key_block)}")

    # (TO BE IMPLEMENTED) append the remaining bytes into the corresponding groups
    # #after decrypting some encrypted bytes, this function calculates a score of the probability the decrypted bytes are english
    def get_english_score(buffer_bytes:bytes):
        # score = 0
        # readable_message = buffer_bytes.decode("utf-8", errors="ignore")
        # print(f"buffer bytes:{buffer_bytes}")
        # print(f"readable message:{readable_message}")
        #create dictionary with frequencies of chars in readable_message excluding some special chars and whitespace chars
        #the list indexes correspond to the alphabet letters 0=>a...26=>z
        observed_char_frequencies = [0 for _ in range(27)]
        total_chars = 0
        # print(len(buffer_bytes))
        for byte in buffer_bytes:
            # c = chr(b).lower()
            # print("current char!!!!!", c)
            if 97 <= byte <= 122:
                observed_char_frequencies[byte - 97] += 1
            total_chars += 1
        #if there is no alphabet letters in decrypted bytes it is not english
        if len(list(filter(lambda x: x != 0, observed_char_frequencies))) == 0:
            return sys.maxsize
        expected_char_frequencies = [total_chars*frequencies.get(chr(byte),0) for byte in range(97,123)]
        # print(f"buffer bytes: {buffer_bytes}\n observed char frequencies: {observed_char_frequencies}\n expected char frequencies: {expected_char_frequencies}")
        return sum([(abs(observed - expected) ** 2) / expected for observed, expected in zip(observed_char_frequencies, expected_char_frequencies)])
        # # print(f"char frequencies: {char_frequencies}")
        # for c in char_frequencies.keys():
        #     #100% == len(message)
        #     #?%  == # occurences of <char>
        #     #message % covered by the occurences of a <char>
        #     char_frequency = char_frequencies[c]
        #     expected_char_frequency = (frequencies[c]*len(buffer_bytes))
        #     # print(f"current char {c}, with frequency: {char_frequency} and expected frequency of: {expected_char_frequency}")
        #     score += (char_frequency - expected_char_frequency)**2/expected_char_frequency
        #     # if c in frequencies.keys():
        #         #using chi-squared test
        # # print(f"Readable message: \n{readable_message}\nChar frequencies: \n{char_frequencies}\nScore:\n{score}\n")
        # #the lowest the score of some readable message it means the higher the likelihood that it's an english message
        # print("score: ", score)
        # return score


    def b_highest_probability_decrypted_bytes(encrypted_bytes:bytes):
        results = []
        for key in range(256):
            decrypted_bytes = xor_decrypt(encrypted_bytes.decode("utf-8"), key)
            # print(f"decrypted bytes length: {len(decrypted_bytes)}")
            # print(f"current key {key} for decrypted block: {decrypted_bytes} with english score: {get_english_score(decrypted_bytes)}")
            # current_probability = sum([frequencies.get(chr(decrypted_byte).lower(),0) for decrypted_byte in decrypted_bytes])
            current_probability_score = get_english_score(decrypted_bytes)
            results.append({"key": key, "bytes": decrypted_bytes, "score": current_probability_score})
        # print(results)
        # results = filter(lambda x: x["score"] != 3.0035700000000007, results)
        return sorted(results, key=lambda x: x['score'])[0:3]

    highest_probability_keys = []
    for key_block in key_blocks:
        # finding the single character key that XOR'd a message and getting the decrypted message
        results = b_highest_probability_decrypted_bytes(key_block)
        # print("keyblock length", len(key_block))
        # highest_probability_keys.append(highest_probability_key)
        # print(highest_probability_key.to_bytes(1, byteorder="big").decode("utf-8"))
        # print(highest_probability_decrypted_b, type(highest_probability_decrypted_b))
        print(f"Results : {results}")

    print(highest_probability_keys)
    # return b_repeating_key_xor_encrypt(repeating_key_xor_encrypted_bytes, highest_probability_keys)





#TESTS
#checking that b_repeating_key_xor can encrypt all ascii (0-256) chars from a message
#base64 encrypt the result of the b_repeating_key_xor
#decrypt the base64 and b_repeating_key_xor and get back the same messahe
def test_break_repeating_key_xor():
    file = open("../repeating_xor_encrypted_hay.txt")
    b64_decoded_file_bytes = b""
    for line in file.readlines():
        # print("striped decoded line", base64.b64decode(bytes(line.strip(), "ascii")).decode("utf-8"))
        b64_decoded_file_bytes += base64.b64decode(bytes(line.strip(), "ascii"))
    # b64_decoded_file_bytes_length = len(b64_decoded_file_bytes)
    break_repeating_key_xor(b64_decoded_file_bytes)
    # cipher = """Hello hello hello """
    # key = "scr"#115 99 114
    # repeating_key_xor_encrypted_cipher = b_repeating_key_xor_encrypt(bytes(cipher, "utf-8"), bytes(key, "utf-8"))
    # print("repeating-key xor encrypted bytes: ",repeating_key_xor_encrypted_cipher)
    # b64_repeating_key_xor_encrypted_cipher = base64.b64encode(repeating_key_xor_encrypted_cipher)
    # print("base64 encoded repeating-key xor enconded bytes: " ,b64_repeating_key_xor_encrypted_cipher)
    # repeating_key_xor_encrypted_cipher = base64.b64decode(b64_repeating_key_xor_encrypted_cipher)
    # print("repeating-key xor encrypted bytes after decoding from base64: ",repeating_key_xor_encrypted_cipher.decode("utf-8"))
    # print("Decrypted message: ", b_repeating_key_xor_encrypt(repeating_key_xor_encrypted_cipher, bytes(key, "utf-8")).decode("utf-8"))
    # print(break_repeating_key_xor(repeating_key_xor_encrypted_cipher))





if __name__ == "__main__":
    test_break_repeating_key_xor()