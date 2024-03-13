from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from pymongo import MongoClient
from bson import ObjectId
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os


from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
from base64 import b64encode, b64decode # For encoding encrypted data
import bcrypt # For password hashing

from algorithms.aes256gcm.aesEncryption import aesEncryption
# from algorithms.aes256gcm.aesDecryption import aesDecryption
# from algorithms.rsaProcess.rsaEncryption import rsaEncryption
# from algorithms.rsaProcess.rsaDecryption import rsaDecryption

app = Flask(__name__)
app.secret_key = "2tc)(h@|HWT4=+8<:ZiUs;(fvd|8;u"
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['ENC_UPLOAD_FOLDER'] = 'static/enc_files'
app.config['IMAGE_FOLDER'] = 'static/images'
app.config['ENC_IMAGE_FOLDER'] = 'static/enc_images'
FILE_EXTENSIONS ={'txt', 'doc', 'docx', 'pdf'}
IMAGE_EXTENSIONS ={'jpeg', 'png', 'jpg', 'raw'}

client = MongoClient(host='project_mongodb', port=27017)
db = client["project_mongodb"]
users_collection = db['users']
files_collection = db['files']
images_collection = db['images']
enc_files_collection = db['enc_files']
enc_images_collection = db['enc_images']

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
                                        file_list=file_list
                                        )
            else:
                flash('Invalid File Type')
                flash('Accepted File Types are txt, doc, docx, pdf')
                return render_template('file-upload.html', 
                                        user = user,
                                        form=form,
                                        user_files=user_files,
                                        file_list=file_list
                                        )

        return render_template('file-upload.html',
                                user = user,
                                form=form,
                                user_files=user_files,
                                file_list=file_list
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
            # Perform Encryption
            output = aesEncryption(input_file, cipher, salt, nonce)
            flash("Encryption success")
        
            # Get the original file extension
            _, original_extension = os.path.splitext(file_to_encrypt["filename"])
            
            # Save encrypted file
            output_filename = secure_filename(file_to_encrypt["filename"][:-len(original_extension)]) + '_encrypted' + original_extension
            output_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                        app.config['ENC_UPLOAD_FOLDER'],
                                        output_filename)
        
            with open(output_path, 'wb') as f:
                f.write(output)

            enc_files_collection.insert_one({
                "user_id": user_id,
                "original_filename": file_to_encrypt["filename"],  # Store original name
                "encrypted_filename": output_filename,
                "encryption_key": aesKey
            })
                
            enc_files_collection.insert_one({"_id": user_id},
                                        {"$set": {"encrypted_file_path": output}})
            flash("Storage success")
            
            return render_template('file-encrypt.html',
                                user = user,
                                user_files=user_files,
                                file_list=file_list)
    
        return render_template('file-encrypt.html',
                                user = user,
                                user_files=user_files,
                                file_list=file_list
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

## TODO : 
