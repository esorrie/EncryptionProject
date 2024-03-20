# Encrypting the AES key with RSA
import rsa
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding



def rsaEncryption(keyPublic, aesKey_bytes):

    pem_header = b"-----BEGIN PUBLIC KEY-----\n"
    pem_footer = b"-----END PUBLIC KEY-----\n"
    combined_pem = pem_header + base64.b64decode(keyPublic) + pem_footer 
        # Load the public key
    public_key_object = load_pem_public_key(combined_pem)

    # Encrypt the AES key (with OAEP padding)
    enc_aesKey = public_key_object.encrypt(
        aesKey_bytes, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    

    # converting enc_aesKey to b64 for transferring 
    b64_enc_aesKey = base64.b64encode(enc_aesKey)

    return b64_enc_aesKey
