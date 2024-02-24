import random

# ========================================== Utilities - Read/Save Files ==========================================
import os
import uuid

def readFile(textfile):
    with open(textfile, "r") as file:
        return file.read()

def saveTofile(textfile, text):
    file = open(textfile, "w")
    file.write(text)
    file.close()

def fileNames():
    unique_id = str(uuid.uuid4().int)[:3]
    keyFile = "key" + unique_id + ".txt"
    return keyFile

def cipherFileName(keyFile):
    unique_id = keyFile[3:6]
    cipherFile = "cipher" + unique_id + ".txt"
    return cipherFile

def decodedFileName(keyFile):
    unique_id = keyFile[3:6]
    decodedFile = "decoded" + unique_id + ".txt"
    return decodedFile

keyFile = fileNames()

# ========================================== Uniform Sampling ==========================================
def bernoulli(p):
    return random.random() < p

def uniform_sampling(number_of_bits):
    p = 0.5
    result = 0
    for _ in range(number_of_bits):
        result <<= 1
        result |= bernoulli(p)
    return result

def convert_to_binary(number, number_of_bits):
    return format(number, f'0{number_of_bits}b')

def convert_to_decimal(binary):
    return int(binary, 2)

# ========================================== Subset Sum PRG ==========================================
def sample_a(n, q):
    a = []
    for i in range(n):
        a.append(uniform_sampling(q))
    return a

# def save_a_to_file(a):
#     a = ' '.join(map(str, a))
#     saveTofile("a.txt", a)

# a = sample_a(80, 160)
# save_a_to_file(a)

def read_a_from_file():
    a = readFile("a.txt")
    a = list(map(int, a.split()))
    return a

def subset_sum_prg(seed):
    a = read_a_from_file()
    q = 2**160
    return sum([a[i] for i in range(len(a)) if (seed >> i) & 1]) % q

# ========================================== Encoding and decoding message ==========================================
def encode_message(msg):
    binary_msg = "".join(format(ord(char), '08b') for char in msg)
    if len(binary_msg) < 160:
        binary_msg = binary_msg + '0'*(160 - len(binary_msg))
    elif len(binary_msg) > 160:
        binary_msg = binary_msg[:160]
    return int(binary_msg, 2)

def decode_message(msg_binary):
    msg_binary = format(msg_binary, '0160b')
    chunks = [msg_binary[i:i+8] for i in range(0, len(msg_binary), 8)]
    msg = ''.join([chr(int(chunk, 2)) for chunk in chunks])
    return msg

# ========================================== Main Logic ==========================================
def keygen():
    s = uniform_sampling(80)
    return s

def encrypt(msg, key):
    cipher = [0,0]
    r = uniform_sampling(80)
    cipher[0] = r
    seed = key ^ r
    g = subset_sum_prg(seed)
    z = g ^ msg
    cipher[1] = z
    return cipher

def decrypt(cipher, key):
    r = cipher[0]
    z = cipher[1]
    seed = key ^ r
    g = subset_sum_prg(seed)
    msg = g ^ z
    return msg

# ========================================== Steps ==========================================
def keygenStep():
    sk = keygen()
    sk = convert_to_binary(sk, 80)
    saveTofile(keyFile, sk)
    msg = f"Key generated and saved to {keyFile}"
    return msg

def encryptStep(inputFile, keyFilePath):
    userInput = readFile(inputFile)
    # if the user input is more than 160 bits, we will only take the first 160 bits and print a warning
    if len(userInput) > 20:
        print("Warning: The input is more than 160 bits. Only the first 160 bits will be considered.")
        userInput = userInput[:20]
    encodedInput = encode_message(userInput)
    if encodedInput == "Invalid Input":
        exit()
    file = open(keyFilePath, "r")
    sk = file.read()
    file.close()
    sk = convert_to_decimal(sk)
    cipher = encrypt(encodedInput, sk)
    #convert list to string
    cipher = ' '.join(map(str, cipher))
    # readCipher = decode_message(cipher)
    cipherFile = cipherFileName(keyFilePath)
    saveTofile(cipherFile, cipher)
    msg = f"Cipher generated and saved to {cipherFile}"
    return msg

def decryptStep(cipherFile, keyFilePath):
    cipher = readFile(cipherFile)
    cipher = list(map(int, cipher.split()))
    # cipher = [int(i) for i in cipher]
    # cipher = encode_message(cipher)
    file = open(keyFilePath, "r")
    sk = file.read()
    file.close()
    sk = convert_to_decimal(sk)
    decrypted = decrypt(cipher, sk)
    decodedInput = decode_message(decrypted)
    # meed to remove the padding (null characters) from the decoded message
    decodedInput = decodedInput.replace('\x00', '')
    decodedFile = decodedFileName(keyFilePath)
    saveTofile(decodedFile, decodedInput)
    msg = f"Decrypted message saved to {decodedFile}"
    return msg

def verify(inputFile, decodedFile):
    userInput = readFile(inputFile)
    decodedInput = readFile(decodedFile)
    if userInput == decodedInput:
        return "Verification successful."
    else:
        return "Verification failed."

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
        print(encryptStep(inputFile, keyFilePath))
    elif choice == "3":
        cipherFile = input("Enter the name of the file to decrypt: ")
        keyFilePath = input("Enter the name of the key file: ")
        print(decryptStep(cipherFile, keyFilePath))
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

print("Welcome to A2 Cipher Program!")
runProg()

