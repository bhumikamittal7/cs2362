'''
Write a program to implement the Substitute Cipher. Your program must have three separate
subprograms: [15]
- KeyGen: This program lets Alice/Bob choose a random permutation π : {0, . . . , 25} →
{0, . . . , 25} from the set of all such permutations as a common secret key sk.
- Enc: This program takes as input an english text and outputs its encryption (as described by
the Substitution Cipher) using the secret key sk = π
- Dec: This program takes as input a ciphertext and decrypts it (as described by the Substitution
Cipher) to a english text, using the secret key sk = π.
'''

#Assumptions:
#1. User input is a string of english letters only (no spaces, no punctuation, no numbers) - all lowercase
#2. User input is a string of length 1 or greater
#======================================================================================================================================================================

import random

def encoding(userInput):
    encodedInput = []
    if userInput.isalpha() and len(userInput) >= 1:
        if userInput.lower() != userInput:
            print("User input must be lowercase, converting to lowercase...")
            userInput = userInput.lower()
        for i in userInput:
            encodedInput.append(ord(i)-97)
        return encodedInput
    else:
        print("User input must be a string of english letters only (no spaces, no punctuation, no numbers) of len atleast 1 - all lowercase")
        return

def keygen():
    #generate a random permutation of the alphabet
    sk = []
    for i in range(0,26):
        sk.append(i)
    random.shuffle(sk)
    return sk

def enc(encodedInput, sk):
    #take in user input and convert to cipher using sk
    cipher = []
    for i in encodedInput:
        cipher.append(sk[i])
    return cipher

def dec(cipher, sk):
    #take in cipher and convert to user input using sk
    decrypted = []
    for i in cipher:
        decrypted.append(sk.index(i))
    return decrypted

def decoded(decrypted):
    #take in decrypted and convert to user input
    userInput = []
    for i in decrypted:
        userInput.append(chr(i+97))
    return userInput

userInput = input("Enter a string: ")
print("User Input: ", userInput)
print("====================================")

encodedInput = encoding(userInput)
print("Encoded Input: ", encodedInput)
print("====================================")

sk = keygen()
print("Secret Key: ", sk)
print("====================================")

cipher = enc(encodedInput, sk)
print("Cipher: ", cipher)
print("====================================")

decrypted = dec(cipher, sk)
print("Decrypted: ", decrypted)
print("====================================")

decodedInput = decoded(decrypted)
print("User Input: ", decodedInput)
print("====================================")

assert userInput == decrypted
print("LFGO!")