from flask import Blueprint, render_template, request, redirect, flash, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from app.firebase import db

auth_bp = Blueprint("auth", __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        user_doc = db.collection('users').document(email)
        if user_doc.get().exists:
            flash('User already exists.')
        else:
            user_doc.set({'email': email, 'password': password})
            flash("Registered successfully.")
            return redirect('/login')
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_doc = db.collection('users').document(email).get()
        if user_doc.exists:
            stored_hash = user_doc.to_dict()['password']
            if check_password_hash(stored_hash, password):
                session['user'] = email
                return redirect('/')
        flash("Invalid credentials.")
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')
