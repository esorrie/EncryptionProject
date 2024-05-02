# Encrypting the AES key with RSA
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
import math
from math import log2

from flask import flash
import psutil
import time

#######
# Here we encrypt the aes key with the recipient public key 
# so the file encryption key (aes key) is safe in transit
# keyPublic = recipient user public key
# aesKey = encryption key used to encrypted sent file data
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
        
        # flash(f"Function '{func.__name__}' Memory Usage: {mem_usage:.4f} MB") 
        # flash(f"Execution Time: {execution_time:.4f} seconds")
        return result
    return wrapper


def calculate_shannon_entropy(encrypted_data):
    # Count the frequency of each byte value
    byte_counts = [0] * 256
    for byte in encrypted_data:
        byte_counts[byte] += 1

    total_bytes = len(encrypted_data)

    # Calculate the Shannon entropy
    entropy = 0
    for count in byte_counts:
        if count > 0:
            p = count / total_bytes
            entropy -= p * log2(p)

    return entropy

@profile_function
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
        ) # adding padding to the aesKey and then encrypting with the RSA public key
    ) # OAEP adds extra protection to the aes key 
    
    entropy = calculate_shannon_entropy(enc_aesKey)
    flash(f"Entropy: {entropy:.4f}")
            
    # converting enc_aesKey to b64 for transferring 
    b64_enc_aesKey = base64.b64encode(enc_aesKey)

    return b64_enc_aesKey
