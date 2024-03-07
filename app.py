from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from pymongo import MongoClient

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
            users_collection.insert_one({'username': username, 'password': password, 'email': email})
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html') 

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_collection.find_one({'username': username, 'password': password})
        if user:
            flash('Login Successful.', 'success')
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html') 



# @app.route('/user')
# def fetch_user():
#     db = get_db()
#     _users = db.user_tb.find()
#     users = [{"id": user["id"], "name": user["name"], "email": user["email"]} for user in _users]
#     return jsonify({"users": users})

if __name__ == '__main__': 
    app.run(host='0.0.0.0', debug=True) 
