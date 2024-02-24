# encryption of file with AES 256 GCM
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from base64 import b64encode
import sys

from tkinter import filedialog
from tkinter import Tk

def aesEncryption():
    # Create a Tkinter root window (it will be hidden)
    root = Tk()
    root.withdraw()

    BUFFER_SIZE = 1024 * 1024 # The size in bytes that we read, encrypt and write to at once

    # Ask the user to select a file using a file dialog
    input_filename = filedialog.askopenfilename()

    # Check if the user selected a file
    if input_filename:
        output_filename = input_filename # file is only created if a file is selected (prevents an empty _encrypted file being created)
        file_out = open(output_filename, 'wb')  # wb = write bytes. Required to write the encrypted data

        # Generating a random salt
        # A salt is random data that is used as an additional input to a one-way function that "hashes" data.
        saltGen = get_random_bytes(32) 
        # key does have to be stored as key changes on user input for password 
        password = input("Enter your password: ")  # Password input by the user
        # Generating the key using scrypt
        aesKey = scrypt(password, saltGen, key_len=32, N=2**20, r=8, p=1)  # Your key that you can encrypt with, N=work factor, r = block size parameter, p = parallelization parameter, it must be no greater than

        cipher = AES.new(aesKey, AES.MODE_GCM)  # Create a cipher object to encrypt data

        # User selected a file, open and read its contents
        with open(input_filename, 'rb') as file_content:
            data = file_content.read(BUFFER_SIZE)  # Read in some of the file
            while len(data) != 0:  # Check if we need to encrypt anymore data
                encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
                file_out.write(encrypted_data)  # Write the encrypted data to the output file
                data = file_content.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

            file_out.write(saltGen)  # Write the salt to the top of the output file
            file_out.write(cipher.nonce)  # Write out the nonce to the output file under the salt

            # Get and write the tag for decryption verification
            tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
            file_out.write(tag)

            # Close out file
            file_out.close()

            # Read the content of the encrypted file and encode it using base64
        with open(output_filename, 'rb') as encrypted_file:
            encrypted_content = encrypted_file.read()
            b64_file_out = b64encode(encrypted_content).decode('utf-8')
    
    else:
        # User canceled the file dialog, end program as no content to encrypt
        print("No file selected")
        sys.exit()

    return aesKey, b64_file_out

