def english_score(decrypted_buffer_bytes):
    #English score function based on chi2 testing
    #frequencies taken from wikipedia letter frequency
    #https://en.wikipedia.org/wiki/Letter_frequency
    #passed values from percent to decimals
    english_frequencies = {"e" : 0.127,"t" : 0.091,"a" : 0.082,"i" : 0.070,"n" : 0.067,"o" : 0.075,"s" : 0.063,"h" : 0.061,"r" : 0.060,"d" : 0.043,"l" : 0.040,"u" : 0.028,"c" : 0.028,"m" : 0.024,"f" : 0.022,"w" : 0.024,"y" : 0.020,"g" : 0.020,"p" : 0.019,"b" : 0.015,"v" : 0.0098,"k" : 0.0077,"q" : 0.00095,"j" : 0.0015,"x" : 0.0015,"z" : 0.00074}
    observed_frequencies = [0 for _ in range(27)]
    for b in decrypted_buffer_bytes:
        #checking for lowercase alphabet letters
        if 97 <= b <= 122:
            observed_frequencies[b-97] += 1
        #checking for uppercase alphabet letters
        elif 65 <= b <= 90:
            observed_frequencies[(b+32)-97] += 1
    #had a lot of issues by using counts, changed to percentage values from both observed and expected frequencies
    observed_frequencies = map(lambda observed_frequency: observed_frequency/len(decrypted_buffer_bytes), observed_frequencies)#percentages of alphabet letters found in decrypted bytes
    expected_frequencies = [100*english_frequencies.get(chr(b), 0) for b in range(97,123)]#percentages of alphabet letters expected to be found in an english text
    return sum([abs(observed - expected)**2/expected for observed, expected in zip(observed_frequencies, expected_frequencies)])

def single_key_xor_encrypt(buffer_bytes, key_byte):
    return bytes([buffer_byte ^ key_byte for buffer_byte in buffer_bytes])

def break_single_key_xor_encryption(buffer_bytes, test_keys):
    results = []
    for key_byte in test_keys:
        decrypted_buffer_bytes = single_key_xor_encrypt(buffer_bytes, key_byte)
        score = english_score(decrypted_buffer_bytes)
        results.append({"key": chr(key_byte), "score": score, "decrypted_bytes": decrypted_buffer_bytes})
    print("Results: ",sorted(results, key=lambda x: x["score"])[0:10])
    return sorted(results, key=lambda x: x["score"])[0]


if __name__ == "__main__":
    cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    bytes_from_cipher = bytes.fromhex(cipher)
    # results = []
    # for key_byte in range(97,123):
    #     decrypted_bytes_from_cipher = single_key_xor_encrypt(bytes_from_cipher, key_byte)
    #     score = english_score(decrypted_bytes_from_cipher)
    #     results.append({"score": score, "decrypted_bytes": decrypted_bytes_from_cipher})
    result = break_single_key_xor_encryption(bytes_from_cipher,list(range(65,91))+list(range(97,123)))
    result2 = break_single_key_xor_encryption(bytes_from_cipher,list(range(256)))
    decrypted_cipher = result["decrypted_bytes"].decode("utf-8")
    print(decrypted_cipher)
    print(result2["decrypted_bytes"].decode("utf-8"))

