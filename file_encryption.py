# file_encryption.py

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_encrypt(data: bytes) -> (bytes, bytes):
    """
    Encrypt `data` with AES-256-GCM.
    Returns a tuple of (nonce||ciphertext||tag, key).
    """
    # 1) Generate a 256-bit key
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)

    # 2) 96-bit nonce is standard for GCM
    nonce = os.urandom(12)

    # 3) Perform encryption; result = ciphertext||tag
    ct_and_tag = aesgcm.encrypt(nonce, data, associated_data=None)

    # 4) Prefix the nonce so we can pull it back out on decrypt
    return nonce + ct_and_tag, key

def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt blob = nonce||ciphertext||tag with AES-256-GCM.
    Returns the original plaintext.
    """
    nonce = blob[:12]
    ct_and_tag = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, associated_data=None)
