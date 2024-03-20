# Encrypting the AES key with RSA
# import rsa
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding


#######
# Here we encrypt the aes key with the recipient public key 
# so the file encryption key (aes key) is safe in transit
# keyPublic = recipient user public key
# aseKey = encryption key used to encrypted sent file data
#######
def rsaEncryption(keyPublic, aesKey):
    
    # Load the public key
    public_key_object = load_pem_public_key(keyPublic)

    # Encrypt the AES key (with OAEP padding)
    enc_aesKey = public_key_object.encrypt(
        aesKey, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    

    # converting enc_aesKey to b64 for transferring 
    b64_enc_aesKey = base64.b64encode(enc_aesKey)

    return b64_enc_aesKey
