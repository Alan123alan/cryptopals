
We get a hex encoded string, which has been XOR'd against a single character, find the key.

The key is a character that was used as an encryption key, brute force until we find a readable message.

How to programmatically check if the decrypted message is a readable message?

Known:
The received string to decode is a hex string

Unknown:

Is the character used as encryption key a hex char, an ascii or utf-8 char?


#### Main task
##### How to score a piece of english plaintext? using character frequency is mentioned, how to implement it? 

Use Samuel Morse frequency table since it has to do with most common words in English and frequency of letters in English vocabulary seems to be less suited for brute forcing a piece of text that will probably contain the most commonly used English words.

Use all ascii characters as possible keys to the cipher.

For each possible ascii character, decode de hex encoded string given by XORing it against the current iteration ascii character then iterate over the characters of the supposed decoded string and assign a value to each character (frequency from Morse's table),  sum all the frequency values for the current decoded string, if the sum is higher than previous values store the decoded string, the key and the sum value.

#### Learnings

##### Most commonly used letters

Samuel Morse found the next table of the most commonly used letters in english to give the shortest codes to them in his Morse code.

| Frequency | Letter    |
| --------- | --------- |
| 12,000    | E         |
| 9,000     | T         |
| 8,000     | A,I,N,O,S |
| 6,400     | H         |
| 6,200     | R         |
| 4,400     | D         |
| 4,000     | L         |
| 3,400     | U         |
| 3,000     | C,M       |
| 2,500     | F         |
| 2,000     | W,Y       |
| 1,700     | G,P       |
| 1,600     | B         |
| 1,200     | V         |
| 800       | K         |
| 500       | Q         |
| 400       | J,X       |
| 200       | Z         |

For word games, it is often the frequency of letters in English vocabulary, regardless of word frequency, which is of more interest. The following is a result of an analysis of the letters occurring in the words listed in the main entries of the _**Concise Oxford Dictionary**_ (9th edition, 1995)

![[frequency of letters in english vocabulary.png]]