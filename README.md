# Encryption of wired/wireless communications and data storage

## AES-256-GCM and RSA for a hybrid crypto-system

---

### Installation/Setup
Prerequisites - Docker

To install the necessary packages, run: 
PyCryptoDome (for aes)- 
```bat
$ docker compose build
```

RSA - 
```bat
$ docker compose up
``` 

---

### AES-256-GCM encryption
When the program is run, a window will pop up allowing you to select the file that you wish to encrypt.
After selecting the file, it will then generate an output filename with "_encrypted" appended at the end.

Then the selected file will be opened and the contents of the file will be read and saved as file_contents.
If no file is selected then the program with stop and no '_encrypted' file will be created.

Once the file has been selected the user is prompted to provide a password that is used to create the encryption key.
This is done after the selection of the file, so a key is only generated when needed to prevent unnecessary key generation.

A cipher will then be created that will be used to encrypt the data, using the generated key and the GCM mode of AES.

The data inside the designated file is then encrypted in 1MB chunks determined by the BUFFER_SIZE that is defined earlier in the code. Once the current chunk of date is encrypted and written to the output file, the next chunk is encrypted until there is no data left to be encrypted.

After all the data is encrypted an authentication tag is provided that allows for authentication during decryption. Then the output and input file is closed.

The 'output_filename' is then reopened and converted to base64.

---

### RSA Asymmetric key Encryption
Once the desired file has been encrypted then the program moves onto encrypting the AES private key with the public key that is generated using RSA encryption algorithm
In this step we are using RSA algorithm which generates two keys, one public and other private. The public key can be shared openly whilst only the recipient should have knowledge of the private key.
