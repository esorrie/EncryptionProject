# Decrypting the AES key with RSA

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

#######
# Here we decrypt the aes key with the recipient private key 
# so the file encryption key (aes key) is useable to decrypt received file
# keyPrivate = recipient user public key
# decrypt_key = the encrypted key that was used to encrypt the received file data
#######
def rsaDecryption(decrypt_key, keyPrivate):

    # Decode from Base64 if necessary
    if isinstance(decrypt_key, bytes):
        decrypt_key = base64.b64decode(decrypt_key)
    
    private_key_object = load_pem_private_key(keyPrivate, password=None)
    
    aesKey = private_key_object.decrypt(
        decrypt_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    b64_aesKey = base64.b64encode(aesKey)

    return b64_aesKey
