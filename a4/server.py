import socket
import random
from petlib.bn import Bn
from petlib.cipher import Cipher
import ast


serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 50000
serverSocket.bind((host, port))

def gen_prime():
    p = Bn.get_prime(128, safe=1)
    p.int_sub(Bn(1))
    p.int_div(Bn(2))
    p = int(p)
    return p

def pick_gen(p):
    while True:
        g = random.randint(2, p-1)
        if pow(g, (p-1)//2, p) != 1 and pow(g, 2, p) != 1:
            return g
        
def pick_alpha(p):
    return random.randint(1, p-1)

def compute_h1(g, alpha, p):
    return pow(g, alpha, p)

def compute_K(h2, alpha, p):
    return pow(h2, alpha, p)

def decrypt(c, v, k):
    mode = Cipher("AES-128-CBC")
    c = ast.literal_eval(c.strip())
    v = ast.literal_eval(v.strip())

    key = k.to_bytes(16, 'big')
    dec = mode.dec(key, v)
    msg = dec.update(c) + dec.finalize()
    return msg.decode()


serverSocket.listen(4)
print("Server is listening for connections")
conn, addr = serverSocket.accept()
print("Connection from: ", addr)

#recieve hello from the client
initMsg = conn.recv(1024).decode()
print("Received: ", initMsg)

p = gen_prime()
g = pick_gen(p)
alpha = pick_alpha(p)
h1 = compute_h1(g, alpha, p)

hello = f"hello {p} {g} {h1}"
print("Sending: ", hello)
conn.send(hello.encode())

h2 = conn.recv(1024).decode()
print("Received: ", h2)

k = compute_K(int(h2), alpha, p)
print("K = ", k)

print("Key exchange complete.")

#recieve C from the client
cip = conn.recv(1024).decode()
c, v = cip.split()
print("Received: ", c)

print("Decoding message...")

#compute msg' = AES.Dec^cbc(C, K)
msgPrime = decrypt(c,v,k)
print("Sending: ", msgPrime)
conn.send(msgPrime.encode())

conn.close()
serverSocket.close()