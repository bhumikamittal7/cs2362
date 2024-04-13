import socket
from petlib.bn import Bn
from petlib.cipher import Cipher
import ast

#Set up the server
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP = '127.0.0.1'
PORT = 5542

serversocket.bind( (IP, PORT) )
serversocket.listen()

#Function to find a generator for a safe prime
def find_generator(p,q):
    while True:
        g_can = p.random()
        
        #Ensure we picka a non-zero generator
        if g_can == 0:
            continue
        
        #Since it is a safe prime of the form 2q+1 we can use this test for a generator
        pow_2 = g_can.pow(2,p)
        pow_q = g_can.pow(q,p)
        
        if pow_2 == 1 or pow_q == 1:
            continue
        
        return g_can
    
#Function to get the public numbers and alpha
def get_public_nums():
    safe_prime = Bn.get_prime(128, safe=True) #Get a safe prime number (2q+1)
    root = safe_prime.int_sub(1).int_div(2) #Get the q from above
    
    assert root.int_mul(2).int_add(1) == safe_prime #Check if the root is correct
    
    generator = find_generator(safe_prime, root) #Get the generator
    
    #Ensure we pick a non-zero alpha
    alpha = 0
    while alpha == 0:
        alpha = safe_prime.random()
    
    h_1 = generator.pow(alpha, safe_prime) #Set h_1
    
    return (safe_prime, generator, h_1, alpha)

#Function to decrypt a message
def aes_decrypt(key, ciphertext, iv):
    aes = Cipher("AES-128-CBC")
    
    ciphertext = ast.literal_eval(ciphertext.strip()) #Convert to bytes
    iv = ast.literal_eval(iv.strip()) #Convert to bytes
        
    aes_key = key.int().to_bytes(16, "big") #Convert key to bytes
    
    dec = aes.dec(aes_key, iv) #Create decryption engine
    
    plaintext = dec.update(ciphertext) + dec.finalize() #Decrypt the message
    
    return plaintext.decode()    
 
#Main loop to handle connections
while True:
    # waiting until client connects
    (clientsocket, address) = serversocket.accept()
    disconnect = False
    print(f"Connection from {address} has been established.")
    
    #Loop to allow multiple handshakes in one connection
    while not disconnect:
        clientsocket.send("Welcome to the server! Send 'hello' to begin a message handshake or 'disconnect' to close the connection".encode()) #Welcome message
        message = clientsocket.recv(1024).decode() #Get message from client
        print(f"Client sent: {message}")
        
        #Disconnect if client sends 'disconnect'
        if message == 'disconnect':
            disconnect = True
            break
        
        #Handhsake if client sends 'hello'
        elif message == 'hello':
            p, g, h_1, alpha = get_public_nums()
            print(f"Generated Safe prime: {p}, Generator: {g}, h_1: {h_1}")
            print(f"Alpha: {alpha}")
            clientsocket.send(f"hello: {p},{g},{h_1}".encode())
            h_2 = clientsocket.recv(1024).decode()
            h_2 = Bn.from_decimal(h_2)
            print(f"Received h_2: {h_2}")
            
            key = h_2.pow(alpha, p) #Set key
            
            print(f"Key set: {key}")
            
            clientsocket.send("Awaiting message".encode()) #Tell client ready to decode
            msg = clientsocket.recv(1024).decode()
            ciphertext, iv = msg.split(",")
            print(f"Received ciphertext: {ciphertext}, IV: {iv}")
            
            decrypted = aes_decrypt(key, ciphertext, iv) #Decrypt message
            print(f"Decrypted message: {decrypted}") #Print decrypted message
            
            clientsocket.send("Message decrypted. Enter y to receive: ".encode()) #Tell client message decrypted
            send_signal = clientsocket.recv(1024).decode() #Get signal from client
            
            if send_signal == 'y':
                clientsocket.send(f"Decrypted: {decrypted}".encode())
                status = clientsocket.recv(1024).decode()
                print(f"Handshake status: {status}")
                print("Resetting key and message\n")
            
        else:
            print("Got invalid input from client \n")
            continue
            
            
    #Disconnect from client
    print("Disconnecting from client!\n")
    clientsocket.send("Disconnecting".encode())
    clientsocket.close()