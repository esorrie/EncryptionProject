from flask import Flask, render_template, request, redirect, session, url_for, flash
from pymongo import MongoClient
from bson import ObjectId

from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from base64 import b64encode # For encoding encrypted data
import bcrypt # For password hashing

app = Flask(__name__)
app.secret_key = "2tc)(h@|HWT4=+8<:ZiUs;(fvd|8;u"

client = MongoClient(host='project_mongodb', port=27017)
db = client["project_mongodb"]
users_collection = db['users']

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
            passwordHash = bcrypt.hashpw(password.encode(), passwordSalt)
            
            
            # Generating a random salt
            # A salt is random data that is used as an additional input to a one-way function that "hashes" data.
            salt = get_random_bytes(32) 
            # Generating the key using scrypt
            aesKey = scrypt(passwordHash, salt=salt, key_len=32, N=2**20, r=8, p=1)  # Your key that you can encrypt with, N=work factor, r = block size parameter, p = parallelization parameter, it must be no greater than
            aesNonce = get_random_bytes(12)
            # Create a cipher object to encrypt data (will use this elsewhere for encrypting and decrypting)
            cipher = AES.new(aesKey, AES.MODE_GCM, nonce=aesNonce)
            
            users_collection.insert_one({
                                        'username': username, 
                                        'email': email,
                                        'password_hash': passwordHash, # storing hash over raw password
                                        'private_Key': keyPrivate,
                                        'public_Key': keyPublic,
                                        'aes_salt': salt, # salt and nonce are stored over the aes key, so you can reconstruct the key when needed rather than storing the key
                                        'aes_nonce': aesNonce
                                        })
            return redirect(url_for('login')) # after register redirect to login page
    return render_template('register.html') 

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_collection.find_one({'username': username, 'password': password})
        if user:
            session['user_id'] = str(user['_id']) # store's user data
            return redirect(url_for('profile')) # after login redirect to home page
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html') 

@app.route('/profile')
def profile():
    if 'user_id' in session:
        user_id = ObjectId(session['user_id'])
        user = users_collection.find_one({'_id': user_id})
        if user:
            return render_template('user.html', user = user)
        else:
            return 'User not found', 404
    else:
        return 'Please log in to view profile', 401 
        
if __name__ == '__main__': 
    app.run(host='0.0.0.0', debug=True) 
