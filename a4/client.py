import socket
import random
from petlib.cipher import Cipher
from os import urandom

def encrypt(key, msg):
    mode = Cipher("AES-128-CBC")
    iv = urandom(16)
    key = key.to_bytes(16, 'big')
    enc = mode.enc(key, iv)
    c = enc.update(msg.encode('utf-8')) + enc.finalize()
    return c, iv

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverHost = "127.0.0.1"
serverPort = 50000

clientSocket.connect((serverHost, serverPort))
print("Connected to the Server. Sending hello....\n")

clientSocket.send("hello".encode('utf-8'))

hello = clientSocket.recv(8192).decode('utf-8')
m, p, g, h1 = hello.split()
p, g, h1 = int(p), int(g), int(h1)

print(" =================== Recieved params =================== ")
print("p = ", p)
print("g = ", g)
print("h1 = ", h1)

beta = random.randint(1, p-1)

#compute h_2 = g^beta mod p
h2 = pow(g, beta, p)
print("h2 =  ", h2)

#send h_2 to the server
clientSocket.send(str(h2).encode('utf-8'))
                  
#compute K = h_1^beta
k = pow(h1, beta, p)
print("Key = ", k)
print(" =================== Key exchange complete =================== ")
print (" Do you want to send a message to the server? Press 'y' to continue or any other key to exit")

choice = input().lower()
if choice != 'y':
    print("Exiting - bye bye!")
    clientSocket.close()
    exit()

#choose a text msg to send to the server
msg = input("Enter your message: ")

# compute C = AES.Enc^cbc(msg, K)
c, v = encrypt(k, msg)
cip = f"{c} {v}"
# send C to the server
clientSocket.send(cip.encode('utf-8'))
print("Cipher sent to the server")

print ("Do you want to recieve a decrypted message from the server? Press 'y' to continue or any other key to exit")
choice = input().lower()
if choice != 'y':
    print("Exiting - bye bye!")
    clientSocket.close()
    exit()

#recieve msg' from the server
msgPrime = clientSocket.recv(8192).decode('utf-8')
print("Received: ", msgPrime)

if msgPrime == msg:
    print("Success")
else:
    print("Failure")
    
clientSocket.close()