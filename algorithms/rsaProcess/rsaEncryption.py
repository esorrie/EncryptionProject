# Encrypting the AES key with RSA
import sys
sys.path.append('/Users/edwardsorrie/Documents/Encryption Dissertation Code/')
from algorithms.aes256gcm.aesEncryption import aesEncryption
import rsa
from base64 import b64encode

def rsaEncryption():

    aesKey, b64_file_out = aesEncryption() # this runs the aesEncryption function so no need to import into main.py

    # generating related asymmetric keys
    publicKey, privateKey = rsa.newkeys(2048)

    # encrypting aesKey with RSA public key
    enc_aesKey = rsa.encrypt(aesKey, publicKey)

    # converting enc_aesKey to b64 for transferring 
    b_64_enc_aesKey = b64encode(enc_aesKey).decode('utf-8')

    # Create payload
    payload = { 'encrypted aes key':b_64_enc_aesKey, 'data': b64_file_out }

    print("\nPayload: ", payload)