import random

def encoding(userInput):
    encodedInput = []
    if userInput.isalpha() and len(userInput) >= 1:
        if userInput.lower() != userInput:
            print("User input must be lowercase, converting to lowercase...")
            userInput = userInput.lower()
        for i in userInput:
            encodedInput.append(ord(i) - 97)
        return encodedInput
    else:
        print("User input must be a string of English letters only (no spaces, no punctuation, no numbers) of length at least 1 - all lowercase")
        return

def keygen():
    # generate a random permutation of the alphabet
    sk = list(range(26))
    random.shuffle(sk)
    return sk

def enc(encodedInput, sk):
    # take in user input and convert to cipher using sk
    cipher = [sk[i] for i in encodedInput]
    return cipher

def dec(cipher, sk):
    # take in cipher and convert to user input using sk
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
