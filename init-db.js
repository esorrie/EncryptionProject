db = db.getSiblingDB("user_db")
db.user_db.drop()

db.user_db.insertMany([
    {
        "id": 1,
        "name": "Admin",
        "email": "admin@admin.com",
        "password": "admin123"
    }
]);