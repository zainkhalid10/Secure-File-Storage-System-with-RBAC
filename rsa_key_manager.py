# rsa_key_manager.py

import rsa
import os

PUBLIC_KEY_PATH  = 'public_key.pem'
PRIVATE_KEY_PATH = 'private_key.pem'

def generate_rsa_keys():
    if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
        pubkey, privkey = rsa.newkeys(2048)
        # write PKCS#1 PEM
        with open(PUBLIC_KEY_PATH , 'wb') as f:
            f.write(pubkey.save_pkcs1('PEM'))
        with open(PRIVATE_KEY_PATH , 'wb') as f:
            f.write(privkey.save_pkcs1('PEM'))

def load_public_key():
    data = open(PUBLIC_KEY_PATH, 'rb').read()
    try:
        # Try PKCS#1 first
        return rsa.PublicKey.load_pkcs1(data)
    except ValueError:
        # Fallback to SPKI/PKCS#8
        return rsa.PublicKey.load_pkcs1_openssl_pem(data)

def load_private_key():
    data = open(PRIVATE_KEY_PATH, 'rb').read()
    try:
        return rsa.PrivateKey.load_pkcs1(data)
    except ValueError:
        return rsa.PrivateKey.load_pkcs1_openssl_pem(data)

def encrypt_key(key: bytes) -> bytes:
    pub = load_public_key()
    return rsa.encrypt(key, pub)

def decrypt_key(encrypted_key: bytes) -> bytes:
    priv = load_private_key()
    return rsa.decrypt(encrypted_key, priv)
