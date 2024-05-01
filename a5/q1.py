import hashlib
import random
import Crypto.PublicKey.RSA as RSA
import Crypto.PublicKey.DSA as DSA
import Crypto.Signature.DSS as DSS
from Crypto.Hash import SHA256
from Crypto.Signature import DSS as DSS_SIG

class User:
    def __init__(self, name, email):
        self.name = name
        self.email = email
        self.RSA_key = RSA.generate(2048)
        self.DSA_key = DSA.generate(2048)

def generate_certificate(subject, issuer, public_key, issuer_private_key):
    cert_data = f"{subject}:{public_key}"
    h = SHA256.new(cert_data.encode('utf-8'))
    signer = DSS_SIG.new(issuer_private_key, 'fips-186-3')
    signature = signer.sign(h)
    return cert_data, signature

def verify_certificate(cert_data, signature, public_key):
    h = SHA256.new(cert_data.encode('utf-8'))
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def CertVerify(cert_chain):
    cert_data_P, signature_P, cert_data_Y, signature_Y = cert_chain
    _, public_key_P = cert_data_P.split(':')
    _, public_key_Y = cert_data_Y.split(':')
    
    if verify_certificate(cert_data_Y, signature_Y, public_key_Y):
        if verify_certificate(cert_data_P, signature_P, public_key_Y):
            return 1
    return 0

# (a) Generate RSA key pair for user P and DSA key pair for user Y
user_P = User("P", "p@example.com")
user_Y = User("Y", "y@example.com")

# (b) Generate certificates
cert_data_P, signature_P = generate_certificate(user_P.email, user_Y.name, user_P.RSA_key.publickey().export_key(), user_Y.DSA_key)
cert_data_Y_self_signed, signature_Y_self_signed = generate_certificate(user_Y.name, user_Y.name, user_Y.DSA_key.publickey().export_key(), user_Y.DSA_key)

# (c) Compute Certificates
cert_Y_to_P = (cert_data_P, signature_P)
cert_Y_self_signed = (cert_data_Y_self_signed, signature_Y_self_signed)

# (d) CertVerify function
certificate_chain = cert_Y_to_P + cert_Y_self_signed
result = CertVerify(certificate_chain)
print("Certificate chain is valid" if result == 1 else "Certificate chain is not valid")