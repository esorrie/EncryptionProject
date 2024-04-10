from json import dump
import shutil
from flask import Flask, render_template, request, redirect, session, url_for, flash
from pymongo import MongoClient
from bson import ObjectId
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
import sys

# from PIL import Image
import cv2

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
from base64 import b64decode # For encoding encrypted data
import bcrypt # For password hashing

from algorithms.aes256gcm.aesEncryption import aesFileEncryption, aesImageEncryption, aesPPMImageEncryption
from algorithms.aes256gcm.aesDecryption import aesFileDecryption, aesImageDecryption
from algorithms.rsaProcess.rsaEncryption import rsaEncryption
from algorithms.rsaProcess.rsaDecryption import rsaDecryption

## TODO : convert any image selected for encryption to .ppm, remove the image header, then grayscale the .ppm image, encrypt image data then add image header back into file

app = Flask(__name__)
app.secret_key = "2tc)(h@|HWT4=+8<:ZiUs;(fvd|8;u"
app.config['UPLOAD_FOLDER'] = 'static/files/files_upload'
app.config['ENC_UPLOAD_FOLDER'] = 'static/files/enc_files'
app.config['ENC_KEY_SENT_FOLDER'] = 'static/files/enc_key_sent'
app.config['DECRYPT_FILE_FOLDER'] = 'static/files/decrypt_file'
app.config['IMAGE_FOLDER'] = 'static/images/images_upload'
app.config['ENC_IMAGE_FOLDER'] = 'static/images/enc_images'
app.config['ENC_KEY_SENT_IMAGE'] = 'static/images/enc_images_sent'
app.config['DECRYPT_IMAGE_FOLDER'] = 'static/images/decrypt_image'
app.config['PPM_IMAGE_FOLDER'] = 'static/images/ppm_images_upload'
app.config['PPM_ENC_IMAGE_FOLDER'] = 'static/images/enc_ppm_images'

FILE_EXTENSIONS ={'txt', 'doc', 'docx', 'pdf'}
IMAGE_EXTENSIONS ={'jpeg', 'png', 'jpg', 'raw', 'ppm'}

client = MongoClient(host='project_mongodb', port=27017)
db = client["project_mongodb"]
users_collection = db['users']
files_collection = db['files']
enc_files_collection = db['enc_files']
sent_files_collection = db['sent_files']
received_files_collection = db['received_files']
decrypted_files_collection = db['decrypted_files']
images_collection = db['images']
enc_images_collection = db['enc_images']
sent_images_collection = db['sent_images']
received_images_collection = db['received_images']
ppm_images_collection = db['ppm_images']
enc_ppm_images_collection = db['enc_ppm_images']

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
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        return render_template('index.html', user=user)

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
            
            users_collection.insert_one({
                                        'username': username, 
                                        'email': email,
                                        'password_hash': passwordHash, # storing hash over raw password
                                        'private_Key': keyPrivate,
                                        'public_Key': keyPublic,
                                        'aes_salt': salt, # salt and nonce are stored over the aes key, so you can reconstruct the key when needed rather than storing the key
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
        recipient_id = user_id
        # flash(user_id)
        # flash(recipient_id)
        
        received_user_files = received_files_collection.find({"recipient_id": recipient_id})        
        received_file_list = [(file['_id'], file['encrypted_filename']) for file in received_files_collection.find({"user_id": user_id})]
        
        received_user_images = received_images_collection.find({"recipient_id": recipient_id})        
        received_images_list = [(image['_id'], image['encrypted_filename']) for image in received_images_collection.find({"user_id": user_id})]
        
        return render_template('user.html', user = user,
                                received_user_files=received_user_files,
                                received_file_list=received_file_list,
                                received_user_images=received_user_images,
                                received_images_list=received_images_list)
    
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
            nonce = get_random_bytes(12)
            
            # Generating the key using scrypt
            # Your key that you can encrypt with, 
            aesKey = scrypt(user['password_hash'],
                            salt=user['aes_salt'],
                            key_len=32,
                            N=2**20, # N=work factor, higher N increases resistance to brute-force attacks
                            r=8, # r = block size parameter, influences the mount of memory required during key derivation
                            p=1) # p = parallelization parameter, useful for running on multiple cores
            flash('AES key generated')
            flash(len(aesKey))
            flash(aesKey)
            
            # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
            cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
            # flash(cipher)
            
            # Construct output filename (assuming the original file directory organization needs to be preserved)
            original_filepath = file_to_encrypt["filename"]
            original_directory, original_filename = os.path.split(original_filepath)  # Split into directory and filename
            _, original_extension = os.path.splitext(original_filename)
            output_filename = original_filename[:-len(original_extension)] + '_encrypted' + original_extension
            
            # save encrypted file 
            encrypted_output_directory = os.path.join(app.config['ENC_UPLOAD_FOLDER'], original_directory)
            os.makedirs(encrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            encrypted_output_path = os.path.join(encrypted_output_directory, output_filename)
        
            # Perform Encryption
            encrypted_output_path = aesFileEncryption(input_file, cipher, nonce, encrypted_output_path)
            flash("Encryption success")
            # flash(output)

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
        # flash(user)
        enc_user_files = enc_files_collection.find({"user_id": user_id})        
        enc_file_list = [(file['_id'], file['encrypted_filename']) for file in enc_files_collection.find({"user_id": user_id})]
        
        users_list = [(user['_id'], user['username']) for user in users_collection.find()]
        
        if request.method == 'POST':
        
            selected_enc_file_id = request.form['selected_enc_file']
            file_to_send = enc_files_collection.find_one({'_id': ObjectId(selected_enc_file_id)})
            # flash(file_to_send)
            recipient_id = request.form['selected_user']
            recipient = users_collection.find_one({'_id': ObjectId(recipient_id)})
            
            keyPublic = recipient['public_Key']
            aesKey = file_to_send['encryption_key']
            # flash("aes key")
            # flash(aesKey) # when called from database auto b64 decoded
            
            # Check if file exists (optional)
            if not file_to_send and recipient:
                flash("Selected file not found")
                return redirect(url_for('file_encrypt', user_id=user_id))
            
            # Construct output filename (assuming the original file directory organization needs to be preserved)
            encrypted_filepath = file_to_send["encrypted_filename"]
            encrypted_directory, encrypted_filename = os.path.split(encrypted_filepath)  # Split into directory and filename
            _, encrypted_extension = os.path.splitext(encrypted_filename)
            sent_output_filename_key = encrypted_filename[:-len(encrypted_extension)] + '_key' + encrypted_extension
            
            send_output = rsaEncryption(keyPublic, aesKey)
            # flash("send_output")
            # flash(send_output)
            
            # save sent encrypted file 
            sent_encrypted_output_directory = os.path.join(app.config['ENC_KEY_SENT_FOLDER'], encrypted_directory)
            os.makedirs(sent_encrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            sent_key_output_path = os.path.join(sent_encrypted_output_directory, sent_output_filename_key)
        
            with open(sent_key_output_path, 'wb') as f:
                f.write(send_output)
            
            sent_files_collection.insert_one({
                "user_id": user_id,
                "encrypted_filename": file_to_send["encrypted_filename"],  # Store encrypted file name
                "sent_encrypted_filename_key": sent_output_filename_key,
                "encryption_key": aesKey,
                "rsa_keyPublic": keyPublic,
                "encrypted_aesKey": send_output,  # to confirm key in file was correct
            })
            flash("Storage success")
            
            received_files_collection.insert_one({
                "recipient_id": recipient['_id'],
                "recipient_username": recipient['username'],
                "encrypted_filename": file_to_send["encrypted_filename"],  # Store encrypted file name
                "sent_encrypted_filename_key": sent_output_filename_key,
                "encryption_key": aesKey,
                "rsa_keyPublic": keyPublic,
                "encrypted_aesKey": send_output, # to confirm key in file was correct
            })
            
            return render_template('file-send.html',
                            user = user,
                            enc_user_files=enc_user_files,
                            enc_file_list=enc_file_list,
                            users_list=users_list,
                            )
            
    return render_template('file-send.html',
                                user = user,
                                enc_user_files=enc_user_files,
                                enc_file_list=enc_file_list,
                                users_list=users_list,
                                )

@app.route('/profile/<user_id>/file-decrypt', methods=['GET', 'POST'])
def file_decrypt(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        recipient_id = user_id
        # flash(user_id)
        # flash(recipient_id)
        
        received_user_files = received_files_collection.find({"recipient_id": recipient_id})        
        received_file_list = [(file['_id'], file['encrypted_filename']) for file in received_files_collection.find({"recipient_id": recipient_id})]
        
        if request.method == 'POST':
            selected_received_file_id = request.form['selected_received_enc_file']
            file_to_decrypt = received_files_collection.find_one({'_id': ObjectId(selected_received_file_id)})
            # flash(file_to_decrypt)
            
            # Check if file exists (optional)
            if not file_to_decrypt:
                flash("Selected file not found")
                return redirect(url_for('file_decrypt', user_id=user_id))
            
            #
            # 
            # FILE DECRYPTION STARTED
            # 
            #
            
            keyPrivate = user['private_Key']
            # flash('Private Key')
            # flash(len(keyPrivate))
            # flash(keyPrivate)
            # # Retrieve absolute file path (assuming files are in 'static/files')
            decrypt_key = file_to_decrypt['encrypted_aesKey']
            # flash('Encrypted aes Key')
            # flash(decrypt_key)
            
            b64_aesKey = rsaDecryption(decrypt_key, keyPrivate)
            # flash('AES Key')
            # flash(b64_aesKey)
            # flash(len(b64_aesKey))
            
            
            aesKey = b64decode(b64_aesKey)            
            # flash(aesKey)
            # flash(b64decode(b64_aesKey))
            # flash(len(b64decode(b64_aesKey)))
            
            b64_decrypt_file = os.path.join(app.config["ENC_UPLOAD_FOLDER"], file_to_decrypt["encrypted_filename"])
            # flash('decrypt file')
            # flash(b64_decrypt_file)

            # Construct output filename (assuming the original file directory organization needs to be preserved)
            original_filepath = file_to_decrypt["encrypted_filename"]
            original_directory, original_filename = os.path.split(original_filepath)  # Split into directory and filename
            base_filename = original_filename.replace("_encrypted", "")
            output_filename = base_filename
            
            # # save decrypted file 
            decrypted_output_directory = os.path.join(app.config['DECRYPT_FILE_FOLDER'], original_directory)
            os.makedirs(decrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            decrypted_output_path = os.path.join(decrypted_output_directory, output_filename)
            
            decrypted_text = aesFileDecryption(b64_decrypt_file, aesKey, decrypted_output_path)
            flash('decryption success')
            # flash(decrypted_text)
            
            return render_template('file-decrypt.html',
                                user = user,
                                received_user_files = received_user_files,
                                received_file_list = received_file_list,
                                )
        return render_template('file-decrypt.html',
                                user = user,
                                received_user_files = received_user_files,
                                received_file_list = received_file_list)
        
    
@app.route('/profile/<user_id>/image-upload', methods=['GET', 'POST'])
def img_upload(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        user_images = images_collection.find({"user_id": user_id})
        images_list = [(image['_id'], image['image_name']) for image in images_collection.find({"user_id": user_id})]
        
        ppm_user_images = ppm_images_collection.find({"user_id": user_id})
        ppm_images_list = [(ppm_image['_id'], ppm_image['ppm_image_name']) for ppm_image in ppm_images_collection.find({"user_id": user_id})]
        
        enc_user_images = enc_images_collection.find({"user_id": user_id})
        enc_images_list = [(image['_id'], image['encrypted_filename']) for image in enc_images_collection.find({"user_id": user_id})]
        
        ppm_enc_user_images = enc_ppm_images_collection.find({"user_id": user_id})
        ppm_enc_images_list = [(ppm_image['_id'], ppm_image['encrypted_ppm_image_name']) for ppm_image in enc_ppm_images_collection.find({"user_id": user_id})]
        
        form = UploadFileForm()
        if form.validate_on_submit():
            image = form.file.data # get file data
            image_name = secure_filename(image.filename)
            if allowedImage(image_name):
                
                original_image_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                        app.config['IMAGE_FOLDER'],
                                        secure_filename(image.filename)) # save file
                image.save(original_image_path)
                
                # 
                # 
                # CONVERTING TO PPM FORMAT
                # 
                # 
                
                img = cv2.imread(original_image_path)
                ppm_image_name = image_name +'.ppm'
                ppm_path = os.path.join(app.config['PPM_IMAGE_FOLDER'], ppm_image_name)
                cv2.imwrite(ppm_path, img, [cv2.IMWRITE_PXM_BINARY, 6])
                
                # 
                # 
                # CONVERTED TO PPM FORMAT
                # 
                # 
                
                images_collection.insert_one({
                    "user_id": user_id,
                    "image_name": image_name,
                })
                
                ppm_images_collection.insert_one({
                    "user_id": user_id,
                    "ppm_image_name": ppm_image_name,
                })
                return render_template('img-upload.html',
                                        user = user,
                                        form=form,
                                        image_name=image_name,
                                        user_images=user_images,
                                        images_list = images_list,
                                        enc_user_images = enc_user_images,
                                        enc_images_list =enc_images_list,
                                        ppm_filename = ppm_image_name,
                                        ppm_enc_user_images = ppm_enc_user_images,
                                        ppm_enc_images_list = ppm_enc_images_list
                                        )    
            else:
                flash('Invalid File Type')
                flash('Accepted File Types are jpeg, png, jpg, raw')
                return render_template('img-upload.html',
                                        user = user,
                                        form=form,
                                        user_images=user_images,
                                        images_list = images_list,
                                        enc_user_images = enc_user_images,
                                        enc_images_list =enc_images_list,
                                        ppm_filename = ppm_image_name,
                                        ppm_enc_user_images = ppm_enc_user_images,
                                        ppm_enc_images_list = ppm_enc_images_list
                                        )
        
        return render_template('img-upload.html',
                                user = user,
                                form=form,
                                user_images=user_images,
                                images_list = images_list,
                                enc_user_images = enc_user_images,
                                enc_images_list =enc_images_list,
                                ppm_user_images = ppm_user_images,
                                ppm_images_list =ppm_images_list,
                                ppm_enc_user_images = ppm_enc_user_images,
                                ppm_enc_images_list = ppm_enc_images_list
                                )
            
@app.route('/profile/<user_id>/image-encrypt', methods=['GET', 'POST'])
def image_encrypt(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        user_images = images_collection.find({"user_id": user_id})
        images_list = [(image['_id'], image['image_name']) for image in images_collection.find({"user_id": user_id})]

        ppm_user_images = ppm_images_collection.find({"user_id": user_id})
        ppm_images_list = [(ppm_image['_id'], ppm_image['ppm_image_name']) for ppm_image in ppm_images_collection.find({"user_id": user_id})]
        
        if request.method == 'POST':
            image_type = request.form['image_type']
            
            if image_type == 'image':
                selected_image_id = request.form['selected_file']
                image_to_encrypt = images_collection.find_one({'_id': ObjectId(selected_image_id)})
            
                input_image = os.path.join(app.config["IMAGE_FOLDER"], image_to_encrypt["image_name"])
                
                salt = user['aes_salt']
                nonce = get_random_bytes(12)
                
                aesKey = scrypt(user['password_hash'],
                                salt=user['aes_salt'],
                                key_len=32,
                                N=2**20, # N=work factor, higher N increases resistance to brute-force attacks
                                r=8, # r = block size parameter, influences the mount of memory required during key derivation
                                p=1) # p = parallelization parameter, useful for running on multiple cores
                
                # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
                cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
            
                # Construct output filename (assuming the original file directory organization needs to be preserved)
                original_imagepath = image_to_encrypt["image_name"]
                original_directory, original_imagename = os.path.split(original_imagepath)
                _, original_extension = os.path.splitext(original_imagename)
                output_imagename = original_imagename[:-len(original_extension)] + '_encrypted' + original_extension
            
                # save encrypted image
                encrypted_output_directory = os.path.join(app.config['ENC_IMAGE_FOLDER'], original_directory)
                os.makedirs(encrypted_output_directory, exist_ok=True)
                encrypted_output_path =os.path.join(encrypted_output_directory, output_imagename)
            
            
                output = aesImageEncryption(input_image, cipher, nonce, encrypted_output_path)
                flash("Encryption success")
            
                enc_images_collection.insert_one({
                    "user_id": user_id,
                    "original_filename": image_to_encrypt["image_name"],  # Store original name
                    "encrypted_filename": output_imagename,
                    "encryption_key": aesKey,
                    "salt": salt,
                    "nonce": nonce,
                })
            
            elif image_type == 'ppm_image':
                selected_image_id = request.form['selected_file']
                ppm_image_to_encrypt = ppm_images_collection.find_one({'_id': ObjectId(selected_image_id)})
            
                ppm_input_image = os.path.join(app.config["PPM_IMAGE_FOLDER"], ppm_image_to_encrypt["ppm_image_name"])
            
                salt = user['aes_salt']
                nonce = get_random_bytes(12)
                
                aesKey = scrypt(user['password_hash'],
                                salt=user['aes_salt'],
                                key_len=32,
                                N=2**20, # N=work factor, higher N increases resistance to brute-force attacks
                                r=8, # r = block size parameter, influences the mount of memory required during key derivation
                                p=1) # p = parallelization parameter, useful for running on multiple cores
                
                # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
                cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
                
                
                # Construct output filename (assuming the original file directory organization needs to be preserved)
                ppm_original_imagepath = ppm_image_to_encrypt["ppm_image_name"]
                original_ppm_directory, original_ppm_imagename = os.path.split(ppm_original_imagepath)
                _, original_ppm_extension = os.path.splitext(original_ppm_imagename)
                output_ppm_imagename = original_ppm_imagename[:-len(original_ppm_extension)] + '_encrypted' + original_ppm_extension
            
                # save encrypted image
                encrypted_ppm_output_directory = os.path.join(app.config['PPM_ENC_IMAGE_FOLDER'], original_ppm_directory)
                os.makedirs(encrypted_ppm_output_directory, exist_ok=True)
                encrypted_ppm_output_path =os.path.join(encrypted_ppm_output_directory, output_ppm_imagename)
            
                ppm_output = aesPPMImageEncryption(ppm_input_image, cipher, nonce, encrypted_ppm_output_path)
                flash("Encryption success")
                
                enc_ppm_images_collection.insert_one({
                "user_id": user_id,
                "original_ppm_filename": ppm_image_to_encrypt["ppm_image_name"],  # Store original name
                "encrypted_ppm_image_name": output_ppm_imagename,
                "encryption_key": aesKey,
                "salt": salt,
                "nonce": nonce,
                })
                
            else:
                flash("Selected image not found")
                return redirect(url_for('image_encrypt', user_id=user_id))
            
            flash("Storage success")
            
            return render_template('img-encrypt.html',
                                user = user,
                                user_images=user_images,
                                images_list_list=images_list,
                                ppm_user_images = ppm_user_images,
                                ppm_images_list = ppm_images_list
                                )
            
        return render_template('img-encrypt.html',
                                user = user,
                                user_images=user_images,
                                images_list = images_list,
                                ppm_user_images = ppm_user_images,
                                ppm_images_list = ppm_images_list
                                )

@app.route('/profile/<user_id>/image-send', methods=['GET', 'POST'])
def image_send(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        # flash(user)
        enc_user_images = enc_images_collection.find({"user_id": user_id})        
        enc_images_list = [(image['_id'], image['encrypted_filename']) for image in enc_images_collection.find({"user_id": user_id})]
        
        users_list = [(user['_id'], user['username']) for user in users_collection.find()]
        
        if request.method == 'POST':
        
            selected_enc_image_id = request.form['selected_enc_image']
            image_to_send = enc_images_collection.find_one({'_id': ObjectId(selected_enc_image_id)})
            
            recipient_id = request.form['selected_user']
            recipient = users_collection.find_one({'_id': ObjectId(recipient_id)})
            
            keyPublic = recipient['public_Key']
            aesKey = image_to_send['encryption_key']
            
            # Check if file exists (optional)
            if not image_to_send and recipient:
                flash("Selected file not found")
                return redirect(url_for('file_encrypt', user_id=user_id))
            
            # Construct output filename (assuming the original file directory organization needs to be preserved)
            encrypted_filepath = image_to_send["encrypted_filename"]
            encrypted_directory, encrypted_imagename = os.path.split(encrypted_filepath)  # Split into directory and filename
            _, encrypted_extension = os.path.splitext(encrypted_imagename)
            sent_output_imagename_key = encrypted_imagename[:-len(encrypted_extension)] + '_key' + encrypted_extension
            
            send_output = rsaEncryption(keyPublic, aesKey)
            
            # save sent encrypted file 
            sent_encrypted_output_directory = os.path.join(app.config['ENC_KEY_SENT_IMAGE'], encrypted_directory)
            os.makedirs(sent_encrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            sent_key_output_path = os.path.join(sent_encrypted_output_directory, sent_output_imagename_key)
        
            with open(sent_key_output_path, 'wb') as f:
                f.write(send_output)
                
            sent_images_collection.insert_one({
                "user_id": user_id,
                "encrypted_filename": image_to_send["encrypted_filename"],  # Store original name
                "sent_encrypted_filename_key": sent_output_imagename_key,
                "encryption_key": aesKey,
                "rsa_keyPublic": keyPublic,
                "encrypted_aesKey": send_output,  # to confirm key in file was correct
            })
            flash("Storage success")
        
            received_images_collection.insert_one({
                "recipient_id": recipient['_id'],
                "recipient_username": recipient['username'],
                "encrypted_filename": image_to_send["encrypted_filename"],  # Store original name
                "sent_encrypted_filename_key": sent_output_imagename_key,
                "encryption_key": aesKey,
                "rsa_keyPublic": keyPublic,
                "encrypted_aesKey": send_output, # to confirm key in file was correct
            })
            
            return render_template('img-send.html',
                            user = user,
                            enc_user_files=enc_user_images,
                            enc_file_list=enc_images_list,
                            users_list=users_list,
                            )
    return render_template('img-send.html',
                                user = user,
                                enc_user_images=enc_user_images,
                                enc_images_list=enc_images_list,
                                users_list=users_list,
                                )

@app.route('/profile/<user_id>/image-decrypt', methods=['GET', 'POST'])
def image_decrypt(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        
        recipient_id = user_id
        # flash(user_id)
        # flash(recipient_id)
        
        received_user_images = received_images_collection.find({"recipient_id": recipient_id})        
        received_images_list = [(image['_id'], image['encrypted_filename']) for image in received_images_collection.find({"recipient_id": recipient_id})]
        
        if request.method == 'POST':
            selected_received_image_id = request.form['selected_received_enc_image']
            image_to_decrypt = received_images_collection.find_one({'_id': ObjectId(selected_received_image_id)})
            # flash(file_to_decrypt)
            
            # Check if file exists (optional)
            if not image_to_decrypt:
                flash("Selected image not found")
                return redirect(url_for('image_decrypt', user_id=user_id))
            
            #
            # 
            # FILE DECRYPTION STARTED
            # 
            #
            
            keyPrivate = user['private_Key']
            # flash('Private Key')
            # flash(len(keyPrivate))
            # flash(keyPrivate)
            # # Retrieve absolute file path (assuming files are in 'static/files')
            decrypt_key = image_to_decrypt['encrypted_aesKey']
            # flash('Encrypted aes Key')
            # flash(decrypt_key)
            
            b64_aesKey = rsaDecryption(decrypt_key, keyPrivate)
            # flash('AES Key')
            # flash(b64_aesKey)
            # flash(len(b64_aesKey))
            aesKey = b64decode(b64_aesKey)            
            flash(aesKey)
            # flash(b64decode(b64_aesKey))
            # flash(len(b64decode(b64_aesKey)))
            
            b64_decrypt_image = os.path.join(app.config["ENC_IMAGE_FOLDER"], image_to_decrypt["encrypted_filename"])
            # flash('decrypt file')
            # flash(b64_decrypt_file)

            # Construct output filename (assuming the original file directory organization needs to be preserved)
            original_filepath = image_to_decrypt["encrypted_filename"]
            original_directory, original_imagename = os.path.split(original_filepath)  # Split into directory and filename
            base_filename = original_imagename.replace("_encrypted", "")
            output_filename = base_filename
            
            # # save decrypted file 
            decrypted_output_directory = os.path.join(app.config['DECRYPT_IMAGE_FOLDER'], original_directory)
            os.makedirs(decrypted_output_directory, exist_ok=True)  # Create the directory if it doesn't exist
            decrypted_output_path = os.path.join(decrypted_output_directory, output_filename)

            decrypted_text = aesImageDecryption(b64_decrypt_image, aesKey, decrypted_output_path)
            flash('decryption success')
            # flash(decrypted_text)
            
            return render_template('img-decrypt.html',
                                user = user,
                                received_user_images = received_user_images,
                                received_images_list = received_images_list,
                                )
        return render_template('img-decrypt.html',
                                user = user,
                                received_user_images = received_user_images,
                                received_images_list = received_images_list)
    

if __name__ == '__main__': 
    app.run(host='0.0.0.0', debug=True) 
