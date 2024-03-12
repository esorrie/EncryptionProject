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
app.config['IMAGE_FOLDER'] = 'static/images'

client = MongoClient(host='project_mongodb', port=27017)
db = client["project_mongodb"]
users_collection = db['users']
files_collection = db['files']
images_collection = db['images']

class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File")

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
        
        # if request.method == 'POST':
        #     input_file = request.files['file']
        #     upload_folder = os.path.join(app.root_path, 'uploads')  # Choose a suitable 'uploads' folder location 
        #     os.makedirs(upload_folder, exist_ok=True)  # Ensure the folder exists
        #     file_path = os.path.join(upload_folder, input_file.filename)
        #     input_file.save(file_path) 
        #     return render_template('uploaded.html', name = input_file.filename)
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
            #     # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
            #     cipher = AES.new(aesKey, AES.MODE_GCM, nonce=user['aes_nonce'])
            #     # Perform Encryption
            #     output = aesEncryption(input_file, cipher, salt, nonce)
            #     flash("Encryption success")
            #     users_collection.update_one({"_id": user_id},
            #                                 {"$set": {"encrypted_file_path": output}})
            #     flash("Storage success")
            #     return render_template('uploaded.html', name = input_file.filename)

                
    else:
        return 'Please log in to view profile', 401 
    
@app.route('/profile/file-upload/<user_id>', methods=['GET', 'POST'])
def file_upload(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        form = UploadFileForm()
        if form.validate_on_submit():
            file = form.file.data # get file data
            file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                    app.config['UPLOAD_FOLDER'],
                                    secure_filename(file.filename))) # save file
            filename = secure_filename(file.filename)
            files_collection.insert_one({
                "user_id": user_id,
                "filename": filename
            })
            
            return render_template('file-upload.html', user = user, form=form, filename=filename)    
        return render_template('file-upload.html', user = user, form=form)
            
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

@app.route('/profile/image-upload/<user_id>', methods=['GET', 'POST'])
def img_upload(user_id):
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        form = UploadFileForm()
        if form.validate_on_submit():
            file = form.file.data # get file data
            file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                        app.config['IMAGE_FOLDER'], 
                                        secure_filename(file.filename)))
            filename = secure_filename(file.filename)
            images_collection.insert_one({
                "user_id": user_id,
                "filename": filename
            }) 
            
            return render_template('img-upload.html', user = user, form=form, filename=filename)    
        return render_template('img-upload.html', user = user, form=form)
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

## TODO : Prevent image files being stored in the files directory and stop files from being stored in the image directory