'''
Write a program to implement the Substitute Cipher. Your program must have three separate subprograms: [15]
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
            print("Convereted User Input: ", userInput)
        for i in userInput:
            encodedInput.append(ord(i) - 97)
        return encodedInput
    else:
        print("User input must be a string of English letters only (no spaces, no punctuation, no numbers) of length at least 1 - all lowercase")
        return "Invalid Input"

def keygen():
    #permutation Pi: {0, . . . , 25} → {0, . . . , 25}
    sk = list(range(26))
    random.shuffle(sk)
    return sk

def enc(encodedInput, sk):
    # encryption
    cipher = [sk[i] for i in encodedInput]
    return cipher

def dec(cipher, sk):
    # decryption
    decrypted = [sk.index(i) for i in cipher]
    return decrypted

def decoded(decrypted):
    # take in decrypted and convert to user input
    decodedInput = [chr(i + 97) for i in decrypted]
    return ''.join(decodedInput)

userInput = input("Enter a string: ")
print("User Input: ", userInput)
print("====================================")

encodedInput = encoding(userInput)
print("Encoded Input: ", encodedInput)
print("====================================")
if encodedInput == "Invalid Input":
    exit()

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

assert userInput.lower() == decodedInput
print("LFGO!")