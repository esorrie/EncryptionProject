# encryption of file with AES 256 GCM
from base64 import b64encode, b64decode
import base64
from flask import flash
import psutil
import time
import math


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

def calculate_entropy(data):
    """Calculates Shannon entropy of a byte string."""
    counts = [data.count(x) for x in range(256)]  # Count occurrences of each byte value
    total = len(data)
    probabilities = [count / total for count in counts if count > 0]  
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

@profile_function
def aesFileEncryption(input_file, cipher, nonce, encrypted_output_path):
    BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once
    
    if input_file:
        with open(encrypted_output_path, 'wb') as file_out: 
            
            file_out.write(nonce)  # Write out the nonce to the top of the output file
            
            # User selected a file, open and read its contents
            with open(input_file, 'rb') as file_content:
                data = file_content.read(BUFFER_SIZE)  # Read in some of the file
                while len(data) != 0:  # Check if we need to encrypt any more data
                    encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
                    b64_encrypted_data = b64encode(encrypted_data)
                    file_out.write(b64_encrypted_data)  # Write the encrypted data to the output file
                    data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

                

                # Get and write the tag for decryption verification
                tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
                file_out.write(tag)


                # Close out file
                file_out.close()
                
        return encrypted_output_path 
    
@profile_function
def aesImageEncryption(input_image, cipher, nonce, encrypted_output_path):
    BUFFER_SIZE = 1024 * 1024
    
    if input_image:
        with open(encrypted_output_path, 'wb') as file_out: 
            print("Starting encryption process")
            file_out.write(nonce) 
            
            with open(input_image, 'rb') as file_content:
                data = file_content.read(BUFFER_SIZE) 
                while len(data) != 0: 
                    encrypted_data = cipher.encrypt(data) 
                    b64_encrypted_data = b64encode(encrypted_data)
                    file_out.write(b64_encrypted_data) 
                    data = file_content.read(BUFFER_SIZE) 

                tag = cipher.digest() 
                file_out.write(tag)

                file_out.close()
                
        return encrypted_output_path 

# 
# 
# METHOD WITH REMOVING THE IMAGE HEADER BEFORE ENCRYPTION 
# 
# 
@profile_function
def aesPPMImageEncryption(ppm_input_image, cipher, nonce, encrypted_ppm_output_path):
    BUFFER_SIZE = 1024 * 1024 
    
    if ppm_input_image:
        with open(ppm_input_image, 'rb') as f:
            header_lines = f.readlines()[:3]
            
        with open(encrypted_ppm_output_path, 'wb') as file_out: 
            
            for line in header_lines:
                file_out.write(line) 
            
            with open(ppm_input_image, 'rb') as file_content:
                data = file_content.read(BUFFER_SIZE) 
                
                while len(data) != 0: 
                    encrypted_data = cipher.encrypt(data) 
                    b64_encrypted_data = b64encode(encrypted_data)
                    file_out.write(b64_encrypted_data)  
                    data = file_content.read(BUFFER_SIZE)  

                tag = cipher.digest()
                
                file_out.close()
                
        return encrypted_ppm_output_path 