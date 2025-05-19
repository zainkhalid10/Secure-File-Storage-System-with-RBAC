# cloud.py

import os
import boto3

REGION    = os.environ.get('AWS_REGION', 'us-east-1')
S3_BUCKET = os.environ['S3_BUCKET']
KMS_ALIAS = os.environ['KMS_KEY_ALIAS']

_s3  = boto3.client('s3', region_name=REGION)
_kms = boto3.client('kms', region_name=REGION)

def generate_data_key():
    resp = _kms.generate_data_key(KeyId=KMS_ALIAS, KeySpec='AES_256')
    return resp['Plaintext'], resp['CiphertextBlob']

def decrypt_data_key(blob):
    resp = _kms.decrypt(CiphertextBlob=blob)
    return resp['Plaintext']

def upload_to_s3(key, data):
    _s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data)

def presign_download(key, expires=300):
    return _s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': S3_BUCKET, 'Key': key},
        ExpiresIn=expires
    )
