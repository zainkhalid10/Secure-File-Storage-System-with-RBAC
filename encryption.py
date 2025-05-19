# encryption.py

import os
import hmac
import hashlib

def generate_hmac_sha256(data: bytes) -> str:
    secret = os.environ.get('HMAC_SECRET_KEY', 'default_hmac_secret').encode()
    return hmac.new(secret, data, hashlib.sha256).hexdigest()
