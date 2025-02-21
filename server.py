from flask import Flask, request, jsonify
# from flask_mysqldb import MySQL
from flask_cors import CORS
from flask_mail import Mail, Message
import logging
import pymysql
import mysql.connector
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)  # Bcrypt initialization
CORS(app)
# Flask-Mail Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"  # Use your email provider's SMTP
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False 
app.config["MAIL_USERNAME"] = "karthickmadasamy7@gmail.com"  # Your email
app.config["MAIL_PASSWORD"] = "kqho easx cfrm rlbj"  # Your email app password
# app.config["MAIL_DEFAULT_SENDER"] = "karthickmadasamy7@gmail.com"  # Optional, default sender address

mail = Mail(app)

# MySQL Connection Function
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Karthick@24",
        database="user_management"
    )

# Create Table if not exists
def create_table():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            role VARCHAR(50) NOT NULL,
            user_id VARCHAR(50) UNIQUE NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    ''')
    db.commit()
    cursor.close()
    db.close()

create_table()

# Get Users
@app.route("/users", methods=['GET'])
def get_users():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT role, user_id, username, email FROM users")
    users = cursor.fetchall()
    cursor.close()
    db.close()
    return jsonify(users)

@app.route("/add_user", methods=['POST'])
def add_user():
    data = request.json
    if not all(key in data for key in ['role', 'id', 'username', 'email', 'password']):
      return jsonify({"error": "Missing fields in request"}), 400
    role = data['role']
    user_id = data['id']
    username = data["username"]
    email = data["email"]
    password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')  # Encrypt password
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)  # Create a new cursor for this request
    try:
       cursor.execute("INSERT INTO users (role, user_id, username, email, password) VALUES (%s, %s, %s, %s, %s)",
                   (role, user_id, username, email, password)
                   )
       db.commit()
    
       return jsonify({"message": "User added successfully"}),201
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()  # Close cursor after use
        db.close()
# dummy baba

@app.route('/get_available_ids', methods=['GET'])
def get_available_ids():
    role = request.args.get('role')  # Get role from query parameters
    if not role:
        return jsonify([])  # Return empty list if no role is selected
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE role=%s", (role,))
    used_ids = [row['user_id'] for row in cursor.fetchall()]
    cursor.close()
    db.close()
    available_ids = [f"{role}{i}" for i in range(1, 4) if f"{role}{i}" not in used_ids]  # Assume IDs are in the form ASM1, RSM1, STORE1, etc.

    return jsonify(available_ids)
# dummy end

# delete a user
@app.route("/delete_user/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)    
    try:
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        db.commit()
        rows_affected = cursor.rowcount  # Number of rows deleted
        cursor.close()
        db.close()        

        if rows_affected == 0:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        cursor.close()
        db.close()        
        return jsonify({"error": str(e)}), 500



@app.route("/update_user/<user_id>", methods=["PUT"])
def update_user(user_id):
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")  # Get password (if provided)

    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400



    query = "UPDATE users SET username=%s, email=%s WHERE user_id=%s"
    values = [username, email, user_id]

    if password and password.strip():  # If password is provided
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        query = "UPDATE users SET username=%s, email=%s, password=%s WHERE user_id=%s"
        values = [username, email, hashed_password, user_id]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
   
    try:
        cursor.execute(query, values)
        db.commit()
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()



# email send password

logging.basicConfig(level=logging.INFO)

@app.route("/emailsend/<user_id>", methods=["PUT", "POST", "GET"])
def send_email(user_id):
    data = request.json
    email = data.get("email")
    new_password = data.get("password", None)
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        # Fetch existing email if not provided
        if not email:
            cursor.execute("SELECT email FROM users WHERE user_id=%s", (user_id,))
            user = cursor.fetchone()
            if user:
                email = user["email"]  # Get existing email from DB

        if not email:
            return jsonify({"error": "Email not found for the user"}), 404

        # Update email in database
        cursor.execute("UPDATE users SET email=%s WHERE user_id=%s", (email, user_id))
        db.commit()

        # If password is provided, hash and update it
        if new_password and new_password.strip():
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
            db.commit()
            logging.info(f"Password updated for user {user_id}")

            # Send Email Notification
            subject = "Password Reset Successful"
            message_body = f"""
            Hello,

            Your password has been successfully reset.

            **New Password:** {new_password}

            Please change it after logging in for security reasons.

            Regards,
            Admin Team
            """
            msg = Message(subject, sender="karthickmadasamy7@gmail.com", recipients=[email])
            msg.body = message_body
            mail.send(msg)
            logging.info(f"Password reset email sent to {email}")

        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        logging.error(f"Error updating user {user_id}: {e}")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500






# Fetch Roles
@app.route('/api/roles', methods=['GET'])
def get_roles():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT DISTINCT role FROM mapping ORDER BY role")
    roles = [row["role"] for row in cursor.fetchall()]
    cursor.close()
    db.close()  
    return jsonify(roles)

# Fetch Role-wise IDs
@app.route('/api/role-data', methods=['GET'])
def get_role_data():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)    
    cursor.execute("SELECT role, user_id FROM mapping ORDER BY role, LENGTH(user_id), user_id")
    data = cursor.fetchall()
    cursor.close()
    db.close()
    
    role_data = {}
    for row in data:
        role = row["role"]
        user_id = row["user_id"]
        if role not in role_data:
            role_data[role] = []
        role_data[role].append(user_id)

    return jsonify(role_data)

if __name__ == "__main__":
    app.run(debug=True)
    
    
    
    
