Decrypt a file, the file has been base64'd after being encrypted using
repeating-key XOR encryption.

first decrypt the base64 encrypted file, from there it's implementing the repeating-key XOR decryption.

Algorithm to break repeating-key XOR encryption provided by cryptopals challenge 6.

1. Guess the keysize, proposed values from 2 to 40
2. Calculate the hamming distance between two strings (per bit)
3. for each keysize take the first and second keysize worth of bytes and calculate the hamming distance between those bytes then divide by the current keysize 