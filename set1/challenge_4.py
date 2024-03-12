from challenge_3 import english_score, single_key_xor_encrypt, break_single_key_xor_encryption





if __name__ == "__main__":
    file = open("../single_xor_encrypted_hay.txt")
    results = []
    for line in file.readlines():
      line_bytes = bytes.fromhex(line.strip())
    #   line_bytes = bytes(line.strip(), "utf-8")
      result = break_single_key_xor_encryption(line_bytes, list(range(256)))
    #   print(result["decrypted_bytes"])
      results.append(result)
    print(sorted(results, key=lambda x: x["score"])[0]["decrypted_bytes"].decode("utf-8"))
      