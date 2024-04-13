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

#send hello to the server
clientSocket.send("hello".encode('utf-8'))

#recieve hello (p, g, h_1) from the server
hello = clientSocket.recv(8192).decode('utf-8')
print("Received: ", hello)
m, p, g, h1 = hello.split()
p, g, h1 = int(p), int(g), int(h1)

#pick a beta uniformly at random from the interval {1, p-1}
beta = random.randint(1, p-1)

#compute h_2 = g^beta mod p
h2 = pow(g, beta, p)

#send h_2 to the server
clientSocket.send(str(h2).encode('utf-8'))
                  
#compute K = h_1^beta
k = pow(h1, beta, p)
print("K = ", k)
print("Key exchange complete")

#choose a text msg to send to the server
msg = input("Enter your message: ")

# compute C = AES.Enc^cbc(msg, K)
c, v = encrypt(k, msg)
cip = f"{c} {v}"
# send C to the server
clientSocket.send(cip.encode('utf-8'))
print("Cipher sent to the server")

#recieve msg' from the server
msgPrime = clientSocket.recv(8192).decode('utf-8')
print("Received: ", msgPrime)

if msgPrime == msg:
    print("Success")
else:
    print("Failure")

clientSocket.close()