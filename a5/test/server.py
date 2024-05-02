import socket
import random
from petlib.bn import Bn
from petlib.cipher import Cipher
import ast
import OpenSSL.crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 50000
serverSocket.bind((host, port))

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
print("Hanshaked - Recieved: ", initMsg)
#================================= 2 done =================================

#generate an RSA key pair
rsa_key = OpenSSL.crypto.PKey()      
rsa_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)  

#Generate DSA pair
dsa_key = OpenSSL.crypto.PKey()
dsa_key.generate_key(OpenSSL.crypto.TYPE_DSA, 2048)

#Self signed certificate
self_cert = OpenSSL.crypto.X509()      
self_cert.get_subject().CN = 'bhumika.mittal_ug24@ashoka.edu.in'   
self_cert.set_serial_number(1000)
self_cert.gmtime_adj_notBefore(0)      
self_cert.gmtime_adj_notAfter(31536000) 
self_cert.set_issuer(self_cert.get_subject())  

self_cert.set_pubkey(dsa_key)              
self_cert.sign(dsa_key, 'sha256')        

print("Self certificate generated")
print("Subject: ", self_cert.get_subject().CN)

enc_cert = OpenSSL.crypto.X509()
enc_cert.get_subject().CN = 'bhumika.mittal_ug24@ashoka.edu.in'
enc_cert.set_serial_number(1001)
enc_cert.gmtime_adj_notBefore(0)
enc_cert.gmtime_adj_notAfter(31536000)
enc_cert.set_issuer(self_cert.get_subject())

enc_cert.set_pubkey(rsa_key)
enc_cert.sign(dsa_key, 'sha256')

print("Enc certificate generated")
print("Subject: ", enc_cert.get_subject().CN)
#================================= 1 done =================================

#convert the certificate to a string and send it to the client
self_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self_cert).decode()
conn.send(self_cert.encode())
print ("self certificate sent")

enc_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, enc_cert).decode()
conn.send(enc_cert.encode())
print ("enc certificate sent")

#================================= 3 done =================================
#recieve C from the client

cip = conn.recv(1024).decode()
e, c, v = cip.split()
#================================= 5 done =================================

Kdash = rsa_key.to_cryptography_key().decrypt(e.to_bytes(16, 'big'), padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None))
msgPrime = decrypt(c,v,Kdash)

#now we have to sign the message using the server's private key and send it back to the client
sign = OpenSSL.crypto.sign(rsa_key, msgPrime, "sha256") 
# print("Signature: ", sign)
#================================= 6 done =================================

#send the signature to the client
tosend = f"{msgPrime} {sign}"
conn.send(tosend.encode())
#================================= 7 done =================================
conn.close()
serverSocket.close()