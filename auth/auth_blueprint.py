from flask import Blueprint, request, session, flash, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, db
from .certificate import generate_certificate
from kyber.kyber import Kyber512
from encrypt import encrypt_with_master_key, MASTER_KEY
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from base64 import b64encode, b64decode

auth_blueprint = Blueprint('auth', __name__)

kyber = Kyber512

# Parámetros de Scrypt para derivación de clave
SALT_LENGTH = 16
KEY_LENGTH = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

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

        if not MASTER_KEY:
            flash('Error interno: MASTER_KEY no configurado.', 'error')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password)

        # Generar el par de claves Kyber512
        public_key, private_key = kyber.keygen()

        # Cifrar la clave privada con la contraseña del usuario usando AES
        salt = os.urandom(SALT_LENGTH)
        derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        iv = os.urandom(16)  # Vector de inicialización para AES en modo CBC
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        encrypted_private_key = iv + salt + cipher.encrypt(pad(private_key, AES.block_size))

        # Validar si el certificado ya existe
        certificate_path = os.path.join('certificates', 'users', f"{username}_certificate.json")
        if os.path.exists(certificate_path):
            flash("El certificado ya existe para este usuario.", "error")
            return render_template('signup.html')

        # Crear certificado para el usuario
        try:
            certificate = generate_certificate(username, public_key.hex())
        except Exception as e:
            flash(f"Error al generar el certificado: {str(e)}", 'error')
            return render_template('signup.html')

        # Crear el nuevo usuario
        new_user = User(
            username=username,
            password=hashed_password,
            public_key_kyber=public_key.hex(),
            private_key_kyber=b64encode(encrypted_private_key).decode('utf-8'),
            certificate_dilithium=certificate
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar el usuario: {str(e)}', 'error')
            return render_template('signup.html')
    return render_template('signup.html')


@auth_blueprint.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
