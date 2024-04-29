#  decryption of file 
import base64
from base64 import b64encode, b64decode # For encoding encrypted data
from Crypto.Cipher import AES
from flask import flash
import psutil
import time

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
def aesFileDecryption(b64_decrypt_file, aesKey, decrypted_output_path):
    BUFFER_SIZE = 1024 * 1024
    
    if b64_decrypt_file:
        with open(decrypted_output_path, 'wb') as file_out:
            
            with open(b64_decrypt_file, 'rb') as file_content:
                # reading the nonce from the beginning of the file
                nonce = file_content.read(12)
                # flash('nonce')
                # flash(nonce)
                
                cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
                # flash('cipher')
                # flash(cipher)
                
                # Get the authentication tag
                file_content.seek(-16,2)
                tag = file_content.read(16) # Read tag at end of file
                # flash('tag')
                # flash(tag)
                
                # flash('file pointer')
                # flash(file_content.tell())
                # flash('b64_decrypt_file length')
                # flash(len(b64_decrypt_file))
                
                file_content.seek(12)
                b64_encrypted_data = file_content.read(BUFFER_SIZE)
                # flash('file pointer')
                # flash(file_content.tell())
                # flash('b_64_encrypted data')
                # flash(b64_encrypted_data)
                
                
                while len(b64_encrypted_data) != 0:
                    encrypted_data = b64decode(b64_encrypted_data)
                    decrypted_data = cipher.decrypt(encrypted_data)
                    file_out.write(decrypted_data)
                    b64_encrypted_data = file_content.read(BUFFER_SIZE)
                    
                cipher.verify(tag) # checks tag before decryption 

            file_out.close()

    return decrypted_output_path

@profile_function
def aesImageDecryption(b64_decrypt_image, aesKey, decrypted_output_path):
    BUFFER_SIZE = 1024 * 1024
    
    if b64_decrypt_image:
        with open(decrypted_output_path, 'wb') as file_out:
            
            with open(b64_decrypt_image, 'rb') as file_content:
                nonce = file_content.read(12)
                cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)

                file_content.seek(-16,2)
                tag = file_content.read(16)
                
                file_content.seek(12)
                b64_encrypted_data = file_content.read(BUFFER_SIZE)
                
                
                while len(b64_encrypted_data) != 0:
                    encrypted_data = b64decode(b64_encrypted_data)
                    decrypted_data = cipher.decrypt(encrypted_data)
                    file_out.write(decrypted_data)
                    b64_encrypted_data = file_content.read(BUFFER_SIZE)


                # cipher.verify(tag)
            file_out.close()

    return decrypted_output_path