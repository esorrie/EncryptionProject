#  decryption of file 
import base64
from Crypto.Cipher import AES
from flask import flash

def aesDecryption(decrypt_file, aesKey, output_filename):
    BUFFER_SIZE = 1024 * 1024
    
    if decrypt_file:
        with open(output_filename, 'wb') as file_out:
            
            with open(decrypt_file, 'rb') as file_content:
                nonce = file_content.read(12)
                cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
                flash('cipher')
                flash(cipher)
                data = file_content.read(BUFFER_SIZE)
                while len(data) != 0:
                    plain_text = cipher.decrypt(data)
                    file_out.write(plain_text)
                    data = file_content.read(BUFFER_SIZE)
                    
                file_out.close()
                
            
        with open(output_filename, 'rb') as plain_file:
            plain_text = plain_file.read()
            return base64.b64encode(plain_file)