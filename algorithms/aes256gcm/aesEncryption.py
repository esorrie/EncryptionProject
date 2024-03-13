# encryption of file with AES 256 GCM
from base64 import b64encode
import os

def aesEncryption(input_file, cipher, salt, nonce):
    BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once
    
    # Check if the user selected a file
    if input_file:
        _, original_extension = os.path.splitext(input_file)
        output_filename = os.path.basename(input_file)[:-len(original_extension)] + '_encrypted' + original_extension

        file_out = open(output_filename, 'wb')  # wb = write bytes. Required to write the encrypted data

        print("Starting encryption process")  # Debug comment

        # User selected a file, open and read its contents
        with open(input_file, 'rb') as file_content:
            data = file_content.read(BUFFER_SIZE)  # Read in some of the file
            while len(data) != 0:  # Check if we need to encrypt anymore data
                encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
                file_out.write(encrypted_data)  # Write the encrypted data to the output file
                data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

            file_out.write(salt)  # Write the salt to the top of the output file
            file_out.write(nonce)  # Write out the nonce to the output file under the salt

            # Get and write the tag for decryption verification
            tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
            file_out.write(tag)

            # Close out file
            file_out.close()

            # Read the content of the encrypted file and encode it using base64
        with open(output_filename, 'rb') as encrypted_file:
            encrypted_content = encrypted_file.read()
            return b64encode(encrypted_content) 


