#============ imports ==================
import socket
import random
from petlib.cipher import Cipher
from os import urandom
import OpenSSL.crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

#================================================================
# ================== utility functions ==========================
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

def verify(msg, sign, pub_key):
    sign = base64.b64decode(sign)
    pub_key = pub_key.to_cryptography_key()
    try:
        pub_key.verify(sign, msg.encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except:
        raise Exception("Verification failed")
    
#================================================================
# ================ connection + handshake =======================
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverHost = "127.0.0.1"
serverPort = 50000

clientSocket.connect((serverHost, serverPort))
print("Connected to the Server. Sending hello....\n")
clientSocket.send("hello".encode('utf-8'))          #SEND 1
#================================================================
# ==================== receive certificates =====================
self_cert = clientSocket.recv(8192).decode('utf-8')
self_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self_cert)
print("Self certificate received")
print("Subject: ", self_cert.get_subject().CN)

enc_cert = clientSocket.recv(8192).decode('utf-8')
enc_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, enc_cert)
print("Enc certificate received")
print("Subject: ", enc_cert.get_subject().CN)
print("==========================================================")
#================================================================
# ==================== verify certificates =====================
store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, self_cert)
store_ctx.verify_certificate()
print("Self certificate verified")

store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store.add_cert(enc_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, enc_cert)
store_ctx.verify_certificate()

verify_cert_chain(self_cert, enc_cert)
print("==========================================================")
#================================================================
# ==================== extract public key =====================
enc_pubkey = enc_cert.get_pubkey()
#================================================================
# ======================== AES keygen ==========================
key = random.getrandbits(128)
#================================================================
# ======================== RSA encryption ======================
e = enc_pubkey.to_cryptography_key().encrypt(key.to_bytes(16, 'big'), padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None))
#================================================================
# ====================== Take message ===========================
print (" Do you want to send a message to the server? Press 'y' to continue or any other key to exit")
choice = input().lower()
if choice != 'y':
    print("Exiting - bye bye!")
    clientSocket.close()
    exit()

msg = input("Enter your message: ")
#remove spaces from the message
msg = msg.replace(" ", "")
#================================================================
# ====================== Encrypt message ========================
c, iv = encrypt(key, msg)
#================================================================
# ====================== Send E, C ===============================
#make sure e doesn't have any spaces
e = base64.b64encode(e).decode('utf-8')
ec = f"{e} {c} {iv}"
print ("Sending E, C to the server")
print(ec)
clientSocket.send(ec.encode('utf-8'))
print(" =================== Cipher Sent =================== ")
#================================================================
# ====================== Signed Message Recieve =================
print ("Do you want to recieve a signed message from the server? Press 'y' to continue or any other key to exit")
choice = input().lower()
if choice != 'y':
    print("Exiting - bye bye!")
    clientSocket.close()
    exit()

sigmaMsg = clientSocket.recv(8192).decode('utf-8')
print("Signed message received")
print(sigmaMsg)
msgPrime, sign = sigmaMsg.split(" ")
#================================================================
# =======================Check correctness and verify======================
# if msgPrime == msg and verify(msgPrime, sign, enc_cert.get_pubkey()):
if msgPrime == msg:
    print("Success")
else:
    print("Failure")

#================================================================
# ===================== Close the connection ===================
clientSocket.close()