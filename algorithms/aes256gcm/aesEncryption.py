# encryption of file with AES 256 GCM
from base64 import b64encode, b64decode
import base64
from flask import flash

def aesFileEncryption(input_file, cipher, nonce, encrypted_output_path):
    BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once
    
    # Check if the user selected a file
    if input_file:
        with open(encrypted_output_path, 'wb') as file_out: 
            print("Starting encryption process")  # Debug comment
            file_out.write(nonce)  # Write out the nonce to the top of the output file
            
            # User selected a file, open and read its contents
            with open(input_file, 'rb') as file_content:
                data = file_content.read(BUFFER_SIZE)  # Read in some of the file
                while len(data) != 0:  # Check if we need to encrypt anymore data
                    encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
                    b64_encrypted_data = b64encode(encrypted_data)
                    file_out.write(b64_encrypted_data)  # Write the encrypted data to the output file
                    data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

                

                # Get and write the tag for decryption verification
                tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
                file_out.write(tag)
                flash('tag')
                flash(tag)

                # Close out file
                file_out.close()
                
        return encrypted_output_path 
    
def aesImageEncryption(input_image, cipher, nonce, encrypted_output_path):
    BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once
    
    if input_image:
        with open(encrypted_output_path, 'wb') as file_out: 
            print("Starting encryption process")
            file_out.write(nonce)  # Write out the nonce to the top of the output file
            
            # User selected a file, open and read its contents
            with open(input_image, 'rb') as file_content:
                data = file_content.read(BUFFER_SIZE)  # Read in some of the file
                while len(data) != 0:  # Check if we need to encrypt anymore data
                    encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
                    b64_encrypted_data = b64encode(encrypted_data)
                    file_out.write(b64_encrypted_data)  # Write the encrypted data to the output file
                    data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

                # Get and write the tag for decryption verification
                tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
                file_out.write(tag)
                # flash('tag')
                # flash(tag)

                # Close out file
                file_out.close()
                
        return encrypted_output_path 

# 
# 
# METHOD WITH CONVERTING TO PPM FORMAT
# 
# 

# def aesImageEncryption(input_image, cipher, nonce, encrypted_output_path):
#     BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once
    
#     if input_image:
#         with open(input_image, 'rb') as f:
#             header_lines = f.readlines()[:3]
            
#         with open(encrypted_output_path, 'wb') as file_out: 
#             # print("Starting encryption process")
#             file_out.write(nonce)  # Write out the nonce to the top of the output file
#             for line in header_lines:
#                 file_out.write(line)  # Encode each line
            
#             # User selected a file, open and read its contents
#             with open(input_image, 'rb') as file_content:
#                 data = file_content.read(BUFFER_SIZE)  # Read in some of the file
                
#                 while len(data) != 0:  # Check if we need to encrypt anymore data
#                     encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
#                     b64_encrypted_data = b64encode(encrypted_data)
#                     file_out.write(b64_encrypted_data)  # Write the encrypted data to the output file
#                     data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

#                 # Get and write the tag for decryption verification
#                 tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
#                 file_out.write(tag)
#                 # flash('tag')
#                 # flash(tag)

#                 # Close out file
#                 file_out.close()
                
#         return encrypted_output_path 