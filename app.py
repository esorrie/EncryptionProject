from bson import ObjectId
from flask import Flask, render_template, request, redirect, session, url_for, flash
from pymongo import MongoClient
from Crypto.PublicKey import RSA

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
            key = RSA.generate(2048)
            keyPrivate = key.export_key('PEM')
            keyPublic = key.publickey().export_key('PEM')
            users_collection.insert_one({
                                        'username': username, 
                                        'password': password,
                                        'email': email,
                                        'private_Key': keyPrivate,
                                        'public_Key': keyPublic
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
