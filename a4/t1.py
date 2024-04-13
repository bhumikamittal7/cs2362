import socket
from petlib.bn import Bn
from petlib.cipher import Cipher
from os import urandom

KEY = None
MSG = None

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Function to encrypt a message
def aes_encrypt(key,msg):
    aes = Cipher("AES-128-CBC")
    
    iv = urandom(16)
    aes_key = key.int().to_bytes(16, "big")
    
    enc = aes.enc(aes_key, iv)
    
    cipher_text = enc.update(msg.encode()) + enc.finalize()
    
    return (cipher_text, iv)

#Function to handle the data from the server in pre-defined schema
def handle_data(data):
    
    global KEY
    global MSG
    
    if data.startswith("Welcome"):
        print(data+": ", end="")
        choice = input()
        return choice
        
    elif data.startswith("hello"):
        nums = data[7:].strip().split(",")
        safe_prime = Bn.from_decimal(nums[0])
        generator = Bn.from_decimal(nums[1])
        h_1 = Bn.from_decimal(nums[2])
        
        print(f"Received Safe prime: {safe_prime}, Generator: {generator}, h_1: {h_1}")
        
        beta = 0
        while beta == 0:
            beta = safe_prime.random()
        
        print(f"Generated beta: {beta}")
        
        h_2 = generator.pow(beta, safe_prime)
        
        print(f"Generated h_2: {h_2}")
        
        KEY = h_1.pow(beta, safe_prime)
        print(f"Key set: {KEY}")
        
        return f"{h_2}"
    
    elif data.startswith("Awaiting"):
        MSG = input("Enter 8-10 word message to send: ")
        ciphertext, iv = aes_encrypt(KEY, MSG)
        return f"{ciphertext}, {iv}"
    
    elif data.startswith("Message"):
        send_signal = input(data)
        return send_signal
    
    elif data.startswith("Decrypted"):
        plaintext = data.split(": ")[1]
        
        status = "success" if plaintext == MSG else "fail"
        
        #Reset the key and the message
        KEY = None
        MSG = None
        
        print(f"Decrypted message: {plaintext}")
        print(f"Handshake status: {status}")
        print("Resetting key and message\n")
        return status #Inform server of status

#Socket details
IP = '127.0.0.1'
PORT = 5542

clientsocket.connect( (IP, PORT) ) #Connect to server

#Loop to communicate with server
while(clientsocket):
    data = clientsocket.recv(1024).decode()
    if(data == "Disconnecting"): #Special disconnection message from server
        print("Disconnecting from Server")
        break
    else:
        response = handle_data(data)
        clientsocket.send(response.encode())

clientsocket.close() #Close connection
print("Connection closed")