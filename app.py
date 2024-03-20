from json import dump
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from pymongo import MongoClient
from bson import ObjectId
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
import sys
from pprint import pprint  # For formatted output

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
from base64 import b64encode, b64decode # For encoding encrypted data
import bcrypt # For password hashing

from algorithms.aes256gcm.aesEncryption import aesEncryption
# from algorithms.aes256gcm.aesDecryption import aesDecryption
from algorithms.rsaProcess.rsaEncryption import rsaEncryption
# from algorithms.rsaProcess.rsaDecryption import rsaDecryption

app = Flask(__name__)
app.secret_key = "2tc)(h@|HWT4=+8<:ZiUs;(fvd|8;u"
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['ENC_UPLOAD_FOLDER'] = 'static/enc_files'
app.config['ENC_RECEIVED_FOLDER'] = 'static/enc_files_received'
app.config['IMAGE_FOLDER'] = 'static/images'
app.config['ENC_IMAGE_FOLDER'] = 'static/enc_images'
app.config['ENC_IMAGE_RECEIVED_FOLDER'] = 'static/enc_images_received'
FILE_EXTENSIONS ={'txt', 'doc', 'docx', 'pdf'}
IMAGE_EXTENSIONS ={'jpeg', 'png', 'jpg', 'raw'}

client = MongoClient(host='project_mongodb', port=27017)
db = client["project_mongodb"]
users_collection = db['users']
files_collection = db['files']
images_collection = db['images']
enc_files_collection = db['enc_files']
sent_files_collection = db['sent_files']
enc_images_collection = db['enc_images']
sent_images_collection = db['sent_images']

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File")

def allowedFile(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in FILE_EXTENSIONS   

def allowedImage(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS   

@app.route('/') 
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST']) 
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if users_collection.find_one({'username': username}):
            flash('Username already exists. Choose a different one.', 'danger')
        else:
            key = RSA.generate(2048) # generates an RSA key pair
            keyPrivate = key.export_key('PEM')
            keyPublic = key.publickey().export_key('PEM')
            
            # Password Hashing (bcrypt)
            passwordSalt = bcrypt.gensalt()  # Generate salt for password hashing
            passwordHash = bcrypt.hashpw(password.encode('utf-8'), passwordSalt)
            
            # Generating a random salt
            # A salt is random data that is used as an additional input to a one-way function that "hashes" data.
            salt = get_random_bytes(32) 
            aesNonce = get_random_bytes(12)
            
            users_collection.insert_one({
                                        'username': username, 
                                        'email': email,
                                        'password_hash': passwordHash, # storing hash over raw password
                                        'private_Key': keyPrivate,
                                        'public_Key': keyPublic,
                                        'aes_salt': salt, # salt and nonce are stored over the aes key, so you can reconstruct the key when needed rather than storing the key
                                        'aes_nonce': aesNonce,
                                        })
            return redirect(url_for('login')) # after register redirect to login page
    return render_template('register.html') 

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_collection.find_one({'username': username})
        if user:
            stored_hash = user['password_hash']  # Retrieve the full hash 
            # Check if the hashed password matches
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['user_id'] = str(user['_id']) # store's user data
                return redirect(url_for('profile', user_id = user['_id'])) # after login redirect to home page
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html') 

@app.route('/profile/<user_id>', methods=['GET', 'POST'])
def profile(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        if user:
            return render_template('user.html', user = user)
    
    return 'Please log in to view profile', 401 
    
@app.route('/profile/<user_id>/file-upload', methods=['GET', 'POST'])
def file_upload(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        user_files = files_collection.find({"user_id": user_id})        
        file_list = [(file['_id'], file['filename']) for file in files_collection.find({"user_id": user_id})]
    
        enc_user_files = enc_files_collection.find({"user_id": user_id})        
        enc_file_list = [(file['_id'], file['encrypted_filename']) for file in enc_files_collection.find({"user_id": user_id})]
        
        form = UploadFileForm()
        if form.validate_on_submit():
            file = form.file.data # get file data
            filename = secure_filename(file.filename)
            if allowedFile(filename):
                file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                        app.config['UPLOAD_FOLDER'],
                                        secure_filename(file.filename))) # save file
                files_collection.insert_one({
                    "user_id": user_id,
                    "filename": filename,
                })
                return render_template('file-upload.html',
                                        user = user,
                                        form=form,
                                        filename=filename,
                                        user_files=user_files,
                                        file_list=file_list,
                                        enc_user_files=enc_user_files,
                                        enc_file_list=enc_file_list,
                                        )
            else:
                flash('Invalid File Type')
                flash('Accepted File Types are txt, doc, docx, pdf')
                return render_template('file-upload.html', 
                                        user = user,
                                        form=form,
                                        user_files=user_files,
                                        file_list=file_list,
                                        enc_user_files=enc_user_files,
                                        enc_file_list=enc_file_list,
                                        )

        return render_template('file-upload.html',
                                user = user,
                                form=form,
                                user_files=user_files,
                                file_list=file_list,
                                enc_user_files=enc_user_files,
                                enc_file_list=enc_file_list,
                                )

@app.route('/profile/<user_id>/file-encrypt', methods=['GET', 'POST'])
def file_encrypt(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        user_files = files_collection.find({"user_id": user_id})        
        file_list = [(file['_id'], file['filename']) for file in files_collection.find({"user_id": user_id})]
        
        if request.method == 'POST':
            selected_file_id = request.form['selected_file']
            file_to_encrypt = files_collection.find_one({'_id': ObjectId(selected_file_id)})

            # Check if file exists (optional)
            if not file_to_encrypt:
                flash("Selected file not found")
                return redirect(url_for('file_encrypt', user_id=user_id))

            # 
            #
            # FILE ENCRYPTION STARTED
            # 
            # 
            
            # Retrieve absolute file path (assuming files are in 'static/files')
            input_file = os.path.join(app.config["UPLOAD_FOLDER"], file_to_encrypt["filename"])
            # File is selected, proceed with encryption
            salt = user['aes_salt']
            nonce = user['aes_nonce']
            # Generating the key using scrypt
            # Your key that you can encrypt with, 
            aesKey = scrypt(user['password_hash'],
                            salt=user['aes_salt'],
                            key_len=32,
                            N=2**20, # N=work factor, higher N increases resistance to brute-force attacks
                            r=8, # r = block size parameter, influences the mount of memory required during key derivation
                            p=1) # p = parallelization parameter, useful for running on multiple cores
            print('AES key generated')
            # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
            cipher = AES.new(aesKey, AES.MODE_GCM, nonce=user['aes_nonce'])
            
            # Construct output filename (assuming the original file directory organization needs to be preserved)
            original_filepath = file_to_encrypt["filename"]
            original_directory, original_filename = os.path.split(original_filepath)  # Split into directory and filename
            _, original_extension = os.path.splitext(original_filename)
            output_filename = original_filename[:-len(original_extension)] + '_encrypted' + original_extension
        
            # Perform Encryption
            output = aesEncryption(input_file, cipher, salt, nonce, output_filename)
            flash("Encryption success")
            

            # save encrypted file 
            encrypted_output_directory = os.path.join(app.config['ENC_UPLOAD_FOLDER'], original_directory)
            os.makedirs(encrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            encrypted_output_path = os.path.join(encrypted_output_directory, output_filename)
        
            with open(encrypted_output_path, 'wb') as f:
                f.write(output)

            # 
            #
            # FILE ENCRYPTION FINISHED
            # 
            # 
            
            enc_files_collection.insert_one({
                "user_id": user_id,
                "original_filename": file_to_encrypt["filename"],  # Store original name
                "encrypted_filename": output_filename,
                "encryption_key": aesKey,
                "salt": salt,
                "nonce": nonce,
            })
            flash("Storage success")
            
            return render_template('file-encrypt.html',
                                user = user,
                                user_files=user_files,
                                file_list=file_list,
                                )
    
        return render_template('file-encrypt.html',
                                user = user,
                                user_files=user_files,
                                file_list=file_list,
                                )

@app.route('/profile/<user_id>/file-send', methods=['GET', 'POST'])
def file_send(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        nonce = user['aes_nonce']
            
        enc_user_files = enc_files_collection.find({"user_id": user_id})        
        enc_file_list = [(file['_id'], file['encrypted_filename']) for file in enc_files_collection.find({"user_id": user_id})]
        
        users_list = [(user['_id'], user['username']) for user in users_collection.find()]
        
        if request.method == 'POST':
            try:
                selected_enc_file_id = request.form['selected_enc_file']
                file_to_send = enc_files_collection.find_one({'_id': ObjectId(selected_enc_file_id)})
                
                recipient_id = request.form['selected_user']
                recipient = users_collection.find_one({'_id': ObjectId(recipient_id)})
                
                keyPublic = recipient['public_Key']
                aesKey = file_to_send['encryption_key']
                aesKey_bytes = base64.b64decode(aesKey) 
                
                # Check if file exists (optional)
                if not file_to_send and recipient:
                    flash("Selected file not found")
                    return redirect(url_for('file_encrypt', user_id=user_id))
                
                # Construct output filename (assuming the original file directory organization needs to be preserved)
                encrypted_filepath = file_to_send["encrypted_filename"]
                encrypted_directory, encrypted_filename = os.path.split(encrypted_filepath)  # Split into directory and filename
                _, encrypted_extension = os.path.splitext(encrypted_filename)
                sent_output_filename = encrypted_filename[:-len(encrypted_extension)] + '_sent' + encrypted_extension
                
                send_output = rsaEncryption(keyPublic, aesKey_bytes)
                
                # save sent encrypted file 
                sent_encrypted_output_directory = os.path.join(app.config['ENC_RECEIVED_FOLDER'], encrypted_directory)
                os.makedirs(sent_encrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
                sent_output_path = os.path.join(sent_encrypted_output_directory, sent_output_filename)
            
                with open(sent_output_path, 'wb') as f:
                    f.write(file_to_send)
                
                sent_files_collection.insert_one({
                    "user_id": user_id,
                    "encrypted_filename": file_to_send["encrypted_filename"],  # Store original name
                    "sent_encrypted_filename": sent_output_filename,
                    # "encryption_key": aesKey,
                    "user_nonce": nonce,
                    "rsa_keyPublic": keyPublic,
                    "encrypted_aesKey": send_output,
                })
                flash("Storage success")
            except Exception as e: 
                print(f"Encryption Error: {e}") 
                
                aesKey_bytes = file_to_send['encryption_key']["$binary"]["base64"]
                key_info = {
                    "type": str(type(aesKey_bytes)),  # Convert type to string for the template
                    "length": len(aesKey_bytes),
                    "first_bytes": aesKey_bytes[:5].hex(),  # Convert to a hex string for display
                    "first_char": aesKey[:5].hex()  # Convert to a hex string for display
                }
            return render_template('file-send.html',
                            user = user,
                            enc_user_files=enc_user_files,
                            enc_file_list=enc_file_list,
                            users_list=users_list,
                            key_info=key_info
                            )
            
    return render_template('file-send.html',
                                user = user,
                                enc_user_files=enc_user_files,
                                enc_file_list=enc_file_list,
                                users_list=users_list,
                                )

@app.route('/profile/<user_id>/image-upload', methods=['GET', 'POST'])
def img_upload(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        form = UploadFileForm()
        user_images = images_collection.find({"user_id": user_id})
        
        if form.validate_on_submit():
            image = form.file.data # get file data
            filename = secure_filename(image.filename)
            if allowedImage(filename):
                image.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                        app.config['IMAGE_FOLDER'],
                                        secure_filename(image.filename))) # save file
                images_collection.insert_one({
                    "user_id": user_id,
                    "filename": filename
                })
                return render_template('img-upload.html',
                                        user = user,
                                        form=form,
                                        filename=filename,
                                        user_images=user_images
                                        )    
            else:
                flash('Invalid File Type')
                flash('Accepted File Types are jpeg, png, jpg, raw')
                return render_template('img-upload.html',
                                        user = user,
                                        form=form,
                                        user_images=user_images
                                        )
        
        return render_template('img-upload.html',
                                user = user,
                                form=form,
                                user_images=user_images
                                )
            
            # if input_file.filename == '':
            #     flash("File not selected")
            # else:
            #     # File is selected, proceed with encryption
            #     salt = user['aes_salt']
            #     nonce = user['aes_nonce']
            #     # Generating the key using scrypt
            #     # Your key that you can encrypt with, 
            #     # N=work factor, higher N increases resistance to brute-force attacks
            #     # r = block size parameter, influences the mount of memory required during key derivation
            #     # p = parallelization parameter, useful for running on multiple cores
            #     aesKey = scrypt(user['password_hash'],
            #                     salt=user['aes_salt'],
            #                     key_len=32,
            #                     N=2**20,
            #                     r=8,
            #                     p=1) 
            #     print('AES key generated')
    
if __name__ == '__main__': 
    app.run(host='0.0.0.0', debug=True) 

## TODO : Use user RSA private key, to encrypt encryption cipher (not AES key)
