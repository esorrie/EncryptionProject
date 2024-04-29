# Decrypting the AES key with RSA
from flask import flash
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
import psutil
import time

#######
# Here we decrypt the aes key with the recipient private key 
# so the file encryption key (aes key) is useable to decrypt received file
# keyPrivate = recipient user public key
# decrypt_key = the encrypted key that was used to encrypt the received file data
#######
def profile_function(func):

    def wrapper(*args, **kwargs):
        process = psutil.Process()
        
        start_time = time.time()
        start_cpu = process.cpu_percent(interval=None)
        start_mem = process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        end_cpu = process.cpu_percent(interval=end_time - start_time)
        end_mem = process.memory_info().rss 

        execution_time = end_time - start_time
        cpu_time = end_cpu - start_cpu 
        mem_usage = (end_mem - start_mem) / (1024 * 1024)
        
        flash(f"Function '{func.__name__}' Memory Usage: {mem_usage:.4f} MB") 
        flash(f"Execution Time: {execution_time:.4f} seconds")
        return result
    return wrapper

@profile_function
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
