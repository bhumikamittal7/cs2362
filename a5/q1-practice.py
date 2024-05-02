import OpenSSL.crypto

#generate an RSA key pair
p_key = OpenSSL.crypto.PKey()       #this function is used to generate a key pair
p_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)   #this function is used to generate a key pair of type RSA and of size 2048


#Generate DSA pair
y_key = OpenSSL.crypto.PKey()
y_key.generate_key(OpenSSL.crypto.TYPE_DSA, 2048)

#Self signed certificate
self_cert = OpenSSL.crypto.X509()       #X509 is a class in the OpenSSL.crypto module that is used to create a certificate object
self_cert.get_subject().CN = 'Kahaan'   #get_subject() is a function that returns the subject of the certificate - CN is a common name, here we are setting the common name to Kahaan
self_cert.set_serial_number(1000)       #set_serial_number() is a function that sets the serial number of the certificate
self_cert.gmtime_adj_notBefore(0)       #The timestamp is formatted as an ASN.1 TIME type and is set to the current time
self_cert.gmtime_adj_notAfter(31536000) #The timestamp is formatted as an ASN.1 TIME type and is set to the current time + 1 year
self_cert.set_issuer(self_cert.get_subject())   #set_issuer() is a function that sets the issuer of the certificate to the subject of the certificate

self_cert.set_pubkey(y_key)                 #set_pubkey() is a function that sets the public key of the certificate 
self_cert.sign(y_key, 'sha256')             #sign() is a function that signs the certificate with the private key of the certificate

#p certificate
p_cert = OpenSSL.crypto.X509()
p_cert.get_subject().CN = 'Bhumika'
p_cert.set_serial_number(1001)
p_cert.gmtime_adj_notBefore(0)
p_cert.gmtime_adj_notAfter(31536000)
p_cert.set_issuer(self_cert.get_subject())

p_cert.set_pubkey(p_key)
p_cert.sign(y_key, 'sha256')

#A function that can extract pkP from CertY →idP /pkP
def get_pubkey(cert):
    key = cert.get_pubkey()         #get_pubkey() is a function that returns the public key of the certificate
    return OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, key).decode('utf-8')      #dump_publickey() is a function that returns the public key in PEM format
                                                                                                #pem is a format for storing and sending cryptographic keys, it is a base64 encoded format

# A function CertVerify for the following task: CertVerify(CertY, CertP) → {true, false}
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
    for cert in chain:
        print("Subject: ", cert.get_subject().CN)
        print("Issuer: ", cert.get_issuer().CN)
        print("Public Key: ", get_pubkey(cert))
    print("Certificate chain verified")


#verify the self certificate
store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, self_cert)
store_ctx.verify_certificate()
print("Self certificate verified")

#verify the p certificate
store = OpenSSL.crypto.X509Store()
store.add_cert(self_cert)
store.add_cert(p_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, p_cert)
store_ctx.verify_certificate()

verify_cert_chain(self_cert, p_cert)

#As a certification authority, consider issuing a certificate binding a subject and an arbitrary key K
# (this need not be a valid public key)

def issue_cert(subject, key):
    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = subject
    cert.set_serial_number(1002)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(self_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(y_key, 'sha256')
    return cert

sub = 'Kahaan 1'
key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
cert = issue_cert(sub, key)

#print the certificate
print("Subject: ", cert.get_subject().CN)
print("Issuer: ", cert.get_issuer().CN)
print("Public Key: ", get_pubkey(cert))

# Write a program AdvCertVerify for the following task:
# Input Cert_CA-> id_s/pk_S and pk_CA (signature scheme is RSA)
#Output: 1 if Cert_CA is valid wrt CA, 0 otherwise

def adv_cert_verify(pk_ca, cert_ca):
    #we will verify the certificate by checking the signature of the certificate
    #with the public key of the CA
    #scheme is RSA
    pass