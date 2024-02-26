from flask import Flask, render_template, jsonify
import pymongo 
from pymongo import MongoClient

app = Flask(__name__)

def get_db():
    client = MongoClient(host='project_mongodb',
                        port=27017,
                        user='root',
                        password='pass',
                        authSource = 'admin')
    db = client["user_db"]
    return db

@app.route('/') 
def index(): 
    return render_template('index.html') 

# app.route('/user')
# def fetch_user():
#     db = get_db
#     _users = db.user_db.find()
#     users = [{"id": user["id"], "name": user["name"], "email": user["email"]} for user in _users]
#     return jsonify({"users": users})

if __name__ == '__main__': 
    app.run(host='0.0.0.0', debug=True) 
