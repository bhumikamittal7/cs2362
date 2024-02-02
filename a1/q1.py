'''
Write a program to implement the Substitute Cipher. Your program must have three separate subprograms: [15]
- KeyGen: This program lets Alice/Bob choose a random permutation π : {0, . . . , 25} →{0, . . . , 25} from the set of all such permutations as a common secret key sk.
- Enc: This program takes as input an english text and outputs its encryption (as described by the Substitution Cipher) using the secret key sk = π
- Dec: This program takes as input a ciphertext and decrypts it (as described by the Substitution Cipher) to a english text, using the secret key sk = π.
'''

#Assumptions:
#1. User input is a string of english letters only (no punctuation, no numbers) - all lowercase
#2. User input is a string of length 1 or greater. Spaces are allowed, but will be removed before encoding
#======================================================================================================================================================================
import random

def cleanFile(text):
    text = text.lower()
    text = text.replace(" ", "")
    text = text.replace("\n", "")
    text = text.replace(".", "")
    text = text.replace(",", "")
    text = text.replace("?", "")
    text = text.replace("!", "")
    text = text.replace(":", "")
    text = text.replace(";", "")
    text = text.replace("-", "")
    text = text.replace("(", "")
    text = text.replace(")", "")
    text = text.replace("'", "")
    text = text.replace('"', "")
    text = text.replace("1", "")
    text = text.replace("2", "")
    text = text.replace("3", "")
    text = text.replace("4", "")
    text = text.replace("5", "")
    text = text.replace("6", "")
    text = text.replace("7", "")
    text = text.replace("8", "")
    text = text.replace("9", "")
    text = text.replace("0", "")
    text = text.replace("/", "")
    text = text.replace("\\", "")
    text = text.replace("|", "")
    text = text.replace("[", "")
    text = text.replace("]", "")
    text = text.replace("{", "")
    text = text.replace("}", "")
    text = text.replace("<", "")
    text = text.replace(">", "")
    text = text.replace("=", "")
    text = text.replace("+", "")
    text = text.replace("_", "")
    text = text.replace("*", "")
    text = text.replace("&", "")
    text = text.replace("^", "")
    text = text.replace("%", "")
    text = text.replace("$", "")
    text = text.replace("#", "")
    text = text.replace("@", "")
    text = text.replace("`", "")
    text = text.replace("~", "")
    return text

def readFile(textfile):
    #read the file and remove all non-alphabetical characters
    file = open(textfile, "r")
    userInput = file.read()
    file.close()
    userInput = cleanFile(userInput)
    return userInput

def encoding(userInput):
    encodedInput = []
    if userInput.isalpha() and len(userInput) >= 1:
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

def readableCipher(cipher):
    readableCipher = [chr(i + 97) for i in cipher]
    return ''.join(readableCipher)

def dec(cipher, sk):
    # decryption

    decrypted = [sk.index(i) for i in cipher]
    return decrypted

def decoded(decrypted):
    # take in decrypted and convert to user input
    decodedInput = [chr(i + 97) for i in decrypted]
    return ''.join(decodedInput)

def saveTofile(textfile, text):
    file = open(textfile, "w")
    file.write(text)
    file.close()

import os
import uuid

def fileNames():
    unique_id = str(uuid.uuid4().int)[:3]
    keyFile = "key" + unique_id + ".txt"
    # cipherFile = "cipher" + unique_id + ".txt"
    # decodedFile = "decoded" + unique_id + ".txt"
    return keyFile

def cipherFileName(keyFile):
    #extract the unique id from the key file name
    unique_id = keyFile[3:6]
    cipherFile = "cipher" + unique_id + ".txt"
    # decodedFile = "decoded" + unique_id + ".txt"
    return cipherFile

def decodedFileName(keyFile):
    #extract the unique id from the key file name
    unique_id = keyFile[3:6]
    decodedFile = "decoded" + unique_id + ".txt"
    return decodedFile

keyFile = fileNames()

def encrypt(inputFile, keyFilePath):
    userInput = readFile(inputFile)
    encodedInput = encoding(userInput)
    if encodedInput == "Invalid Input":
        exit()
    #read the key from the key file
    file = open(keyFilePath, "r")
    sk = file.read()
    file.close()
    sk = list(map(int, sk.split()))
    cipher = enc(encodedInput, sk)
    readCipher = readableCipher(cipher)
    cipherFile = cipherFileName(keyFilePath)
    saveTofile(cipherFile, readCipher)
    msg = "Cipher generated and saved to cipher.txt"
    return msg


def keygenStep():
    sk = keygen()
    #convert sk to string such that each element is separated by a space
    sk = ' '.join(map(str, sk))
    saveTofile(keyFile, sk)
    msg = "Key generated and saved to key.txt"
    return msg

def decrypt(cipherFile, keyFilePath):
    #read the cipher from the cipher file
    cipher = readFile(cipherFile)
    cipher = encoding(cipher)
    #read the key from the key file
    file = open(keyFilePath, "r")
    sk = file.read()
    file.close()
    sk = list(map(int, sk.split()))
    # print(sk)
    decrypted = dec(cipher, sk)
    decodedInput = decoded(decrypted)
    decodedFile = decodedFileName(keyFilePath)
    saveTofile(decodedFile, decodedInput)
    msg = "Decrypted message saved to decoded.txt"
    return msg

def verify(inputFile, decodedFile):
    #read the input from the input file
    userInput = readFile(inputFile)
    #read the decoded from the decoded file
    decodedInput = readFile(decodedFile)
    if userInput == decodedInput:
        return "LFGOOOO"
    else:
        return "Messed up somewhere bruhhh ughhh"


def runProg():
    print("Please select one of the following options:")
    print("1. Keygen")
    print("2. Encrypt")
    print("3. Decrypt")
    print("4. Verify")
    print("5. Exit")
    choice = input("Enter your choice: ")
    if choice == "1":
        print(keygenStep())
    elif choice == "2":
        inputFile = input("Enter the name of the file to encrypt: ")
        keyFilePath = input("Enter the name of the key file: ")
        print(encrypt(inputFile, keyFilePath))
    elif choice == "3":
        cipherFile = input("Enter the name of the file to decrypt: ")
        keyFilePath = input("Enter the name of the key file: ")
        print(decrypt(cipherFile, keyFilePath))
    elif choice == "4":
        inputFile = input("Enter the name of the input file: ")
        decodedFile = input("Enter the name of the decoded file: ")
        print(verify(inputFile, decodedFile))
    elif choice == "5":
        exit()
    else:
        print("Invalid choice. Please try again.")
    print("=====================================================================================================")
    runProg()

print("Welcome to the Substitution Cipher Program!")
runProg()

'''
1. have an option to keygen, enc, dec
2. save keygen to something
3. take input + key file and encrypt and save that to cipher file
4. take cipher file + key file and decrypt and save that to decrypted file
5. do the verification thing -- correctness!
'''

