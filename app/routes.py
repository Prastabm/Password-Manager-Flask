import random, string
from flask import Blueprint, render_template, request, redirect, session
from app.firebase import db
from functools import wraps
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

main = Blueprint("main", __name__)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return fn(*args, **kwargs)
    return wrapper

SECRET_KEY = b'your-actual-secure-key-here'


# Generate a key for encryption
def generate_key(user_id):
    # Use PBKDF2 to derive a key from the user_id and a secret key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SECRET_KEY,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(user_id.encode()))
    return Fernet(key)


def store_password(user_id, account, domain, password):
    cipher_suite = generate_key(user_id)
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    # Store the encrypted password in Firestore
    db.collection('users').document(user_id).collection('passwords').document(account).set({
        'domain': domain,
        'password': encrypted_password
    })
def get_password(user_id, encrypted_password):
    try:
        cipher_suite = generate_key(user_id)
        return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {str(e)}")  # For debugging
        return "**Error: Cannot decrypt password**"

@main.route('/healthz')
def health_check():
    return "OK", 200

@main.route('/')
def landing():
    # If user is already logged in, redirect to dashboard
    if 'user' in session:
        return redirect('/dashboard')
    return render_template("landing.html")

@main.route('/logout')
@login_required
def logout():
    session.clear()  # Clear all session data
    return redirect('/')

@main.route('/dashboard')
@login_required
def index():
    return render_template("index.html")

@main.route('/add', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        account = request.form['account']
        domain = request.form['domain']
        password = request.form['password']
        user = session['user']

        store_password(user, account, domain, password)

        return redirect('/view')
    return render_template('add.html')

@main.route('/view')
@login_required
def view_passwords():
    user = session['user']
    passwords_ref = db.collection('users').document(user).collection('passwords')
    docs = passwords_ref.stream()


    
    # Decrypt passwords before displaying
    entries = []
    for doc in docs:
        data = doc.to_dict()
        try:
            decrypted_password = get_password(user,data['password'])
            entries.append({
                'account': doc.id,
                'domain': data['domain'],
                'password': decrypted_password
            })
        except Exception as e:
            print(f"Error processing entry {doc.id}: {str(e)}")  # For debugging
            entries.append({
                'account': doc.id,
                'domain': data['domain'],
                'password': '**Error: Cannot decrypt password**'
            })

    return render_template("view.html", entries=entries)

@main.route('/update/<account>', methods=['GET', 'POST'])
@login_required
def update_password(account):
    user = session['user']
    doc_ref = db.collection('users').document(user).collection('passwords').document(account)
    cipher_suite = generate_key(user)

    if request.method == 'POST':
        new_domain = request.form['domain']
        new_password = request.form['password']
        
        # Encrypt the new password before storing
        store_password(user, account, new_domain, new_password)
        return redirect('/view')

    doc = doc_ref.get()
    if not doc.exists:
        return "Account not found", 404

    data = doc.to_dict()
    # Decrypt password for display in form
    decrypted_password = get_password(user, data['password'])
    return render_template('update.html', account=account, data={
        'domain': data['domain'],
        'password': decrypted_password
    })


@main.route('/delete/<account>', methods=['POST'])
@login_required
def delete_password(account):
    user = session['user']
    db.collection('users').document(user).collection('passwords').document(account).delete()
    return redirect('/view')
@main.route('/generate', methods=['GET', 'POST'])
@login_required
def generate_password():
    password = ""
    if request.method == 'POST':
        length = int(request.form['length'])
        charset = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(charset) for _ in range(length))
    return render_template('generate.html', password=password)
