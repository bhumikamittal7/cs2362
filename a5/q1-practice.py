import OpenSSL.crypto

#generate an RSA key pair
p_key = OpenSSL.crypto.PKey()
p_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)


#Generate DSA pair
y_key = OpenSSL.crypto.PKey()
y_key.generate_key(OpenSSL.crypto.TYPE_DSA, 2048)

#Self signed certificate
self_cert = OpenSSL.crypto.X509()
self_cert.get_subject().CN = 'Kahaan'
self_cert.set_serial_number(1000)
self_cert.gmtime_adj_notBefore(0)
self_cert.gmtime_adj_notAfter(31536000)
self_cert.set_issuer(self_cert.get_subject())

self_cert.set_pubkey(y_key)
self_cert.sign(y_key, 'sha256')

#p certificate
p_cert = OpenSSL.crypto.X509()
p_cert.get_subject().CN = 'Bhumika'
p_cert.set_serial_number(1001)
p_cert.gmtime_adj_notBefore(0)
p_cert.gmtime_adj_notAfter(31536000)
p_cert.set_issuer(self_cert.get_subject())

p_cert.set_pubkey(p_key)
p_cert.sign(y_key, 'sha256')

def get_pubkey(cert):
    key = cert.get_pubkey()
    return OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, key).decode('utf-8')

def verify_cert_chain(self_cert, p_cert):
    store = OpenSSL.crypto.X509Store()
    store.add_cert(self_cert)
    store.add_cert(p_cert)
    store_ctx = OpenSSL.crypto.X509StoreContext(store, p_cert)
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

