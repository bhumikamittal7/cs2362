import socket
import random
from petlib.cipher import Cipher
from os import urandom
import OpenSSL.crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def get_pubkey(cert):
    key = cert.get_pubkey()         #get_pubkey() is a function that returns the public key of the certificate
    return OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, key).decode('utf-8')    

def verify_cert_chain(self_cert, p_cert):
    store = OpenSSL.crypto.X509Store()      #describe a context in which to verify a certificate
    store.add_cert(self_cert)               #add_cert() is a function that adds a certificate to the store
    store.add_cert(p_cert)
    store_ctx = OpenSSL.crypto.X509StoreContext(store, p_cert)      #here the context is created with the store and the certificate to be verified as the parameter
    try:
        store_ctx.verify_certificate()
    except:
        print("Certificate chain not verified")
        return
    chain = store_ctx.get_verified_chain()
    print("Certificate chain verified")


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
#================================= 2 done =================================

self_cert = clientSocket.recv(8192).decode('utf-8')
self_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self_cert)
print("Self certificate received")
print("Subject: ", self_cert.get_subject().CN)

enc_cert = clientSocket.recv(8192).decode('utf-8')
enc_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, enc_cert)
print("Self certificate received")
print("Subject: ", enc_cert.get_subject().CN)
print("==========================================================")


#verify the self certificate
store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, self_cert)
store_ctx.verify_certificate()
print("Self certificate verified")

#verify the p certificate
store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store.add_cert(enc_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, enc_cert)
store_ctx.verify_certificate()

verify_cert_chain(self_cert, enc_cert)
print("==========================================================")

pk_enccert = get_pubkey(enc_cert)
# print("Public Key: ", pk_enccert)
pk_enccert = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM, pk_enccert)

# toPrintPK = get_pubkey(self_cert)

#pick a K unfiformly at random from AES.keyspace
k = random.randint(0, 2**128-1)
#compute E = RSA.Enc(pk_enccert, K)
#encrypt the key k using the public key of the encryption certificate
e = pk_enccert.to_cryptography_key().encrypt(k.to_bytes(16, 'big'), padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None))
#ERORR here due to padding!!
print(" =================== Key generated =================== ")


#================================== 4 done ==================================
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
cip = f"{e} {c} {v}"
print("Cipher generated")
print(cip)
print("==========================================================")

# send C to the server
clientSocket.send(cip.encode('utf-8'))
# print("Cipher sent to the server")

print ("Do you want to recieve a signed message from the server? Press 'y' to continue or any other key to exit")
choice = input().lower()
if choice != 'y':
    print("Exiting - bye bye!")
    clientSocket.close()
    exit()

#recieve msg' from the server
tosend = clientSocket.recv(8192).decode('utf-8')
msgPrime, sign = tosend.split()

# print("Received: ", msgPrime)

if msgPrime == msg and OpenSSL.crypto.verify(pk_enccert, sign, msgPrime, 'sha256'):
    print("Success")
else:
    print("Failure")
    
clientSocket.close()