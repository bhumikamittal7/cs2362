import socket

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'  #localhost
port = 50000
serverSocket.bind((host, port))

import random
import petlib

# generate a 128-bit prime p using petlib safe prime function



# Consider the group G = Z_p^* (the multiplicative group of integers modulo p)
# pick g \in G uniformly at random such that g is a generator of G


# pick an alpha uniformly at random from the interval {1, p-1}
def generate_alpha(p):
    return random.randint(1, p-1)

# compute h_1 = g^alpha mod p
def compute_h_1(g, alpha, p):
    return pow(g, alpha, p)

# send hello (p, g, h_1) to the client

# recieve h_2 from the client

# compute K = h_2^alpha

# recieve C from the client

# compute msg' = AES.Dec^cbc(C, K)

# send msg' to the client

def userChoice():
    try:
        data = clientSocket.recv(8192)
        if not data:
            raise Exception("No data received")
        choice = int(data.decode('utf-8'))
        return choice
    except Exception as e:
        print(f"Error getting user choice: {e}")
        return -1


serverSocket.listen(4) 
print("Server is waiting for a connection ....")
clientSocket, address = serverSocket.accept()
print(f"connection from: {address}")

while True:
    try:
        choice = userChoice()

        if choice == 1:
            #recieve hello from the client
            hello = clientSocket.recv(8192).decode('utf-8')
            print(hello)

    except Exception as e:
        print(f"Error: {e}")
        break

clientSocket.close()
serverSocket.close()
print("Connection closed")