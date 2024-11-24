from flask import Blueprint, request, session, flash, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from .models import db
from .certificate import generate_certificate
from kyber.kyber import Kyber512
from encrypt import encrypt_with_master_key, MASTER_KEY

auth_blueprint = Blueprint('auth', __name__)

kyber = Kyber512

ENTITY_PUBLIC_KEY = "Some value - I don't know which one"

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('upload_page'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')


@auth_blueprint.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password)

        # Generar el par de claves Kyber512
        public_key, private_key = kyber.keygen()

        # Cifrar la clave privada con ENCRYPTION_KEY
        encrypted_private_key = encrypt_with_master_key(private_key, MASTER_KEY)
        certificate = generate_certificate(username, public_key.hex(), ENTITY_PUBLIC_KEY)

        # Crear el nuevo usuario
        new_user = User(
            username=username,
            password=hashed_password,
            public_key_kyber=public_key.hex(),
            private_key_kyber=encrypted_private_key,
            certificate_dilithium=certificate
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
    return render_template('signup.html')



@auth_blueprint.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))