# Substitution Cipher Program

## Introduction

This Python program implements the Substitution Cipher, which is a simple encryption technique. The program provides three separate subprograms: KeyGen, Enc, and Dec.

### Subprograms:

1. **KeyGen:**
   - This program allows the user (Alice/Bob) to generate a random permutation π: {0, . . . , 25} →{0, . . . , 25} as a common secret key sk. The generated key is saved to a text file.

2. **Enc:**
   - Takes an English text as input and encrypts it using the secret key sk = π, as described by the Substitution Cipher. The encrypted text is saved to a cipher file.

3. **Dec:**
   - Takes a ciphertext as input and decrypts it using the secret key sk = π, reversing the process of encryption. The decrypted text is saved to a file.

## Assumptions:

1. User input is a string of English letters only (no punctuation, no numbers) - all lowercase.
2. User input is a string of length 1 or greater. Spaces are allowed but will be removed before encoding.

## How to Use:

1. **KeyGen:**
   - Run the program and choose option 1 to generate a key.
   - The generated key is saved to a file named 'key.txt'.

2. **Encrypt (Enc):**
   - Choose option 2 and provide the name of the file containing the text to encrypt.
   - Enter the name of the key file (e.g., 'key.txt').
   - The encrypted text is saved to a file named 'cipher.txt'.

3. **Decrypt (Dec):**
   - Choose option 3 and provide the name of the file containing the ciphertext.
   - Enter the name of the key file used for encryption.
   - The decrypted text is saved to a file named 'decoded.txt'.

4. **Verify:**
   - Choose option 4 and provide the name of the input file (plaintext) and the name of the file containing the decrypted text.
   - The program verifies whether the decryption process is correct.

5. **Exit:**
   - Choose option 5 to exit the program.


## Remarks:
- The program removes non-alphabetical characters and converts all input to lowercase during processing.
- Each run generates a unique key file using a unique identifier.
- The key file, cipher file, and decoded file are automatically named based on the unique identifier.
- The program allows for key generation, encryption, decryption, and verification of correctness.
