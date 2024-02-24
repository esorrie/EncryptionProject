from aes256gcm.aesEncryption import aesKey
from rsaEncryption import b_64_enc_aesKey, payload
import rsa
from cryptography.fernet import Fernet
from base64 import b64decode

def rsaDecryption():

    # Decode the symmetric key from base64
    b_64_enc_aesKey = b64decode(payload['key'])
