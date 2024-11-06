from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import json
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from utils import allowed_file, get_user_files, load_json, save_json
from models import db, User
from encriptar import encrypt_file, decrypt_file, is_strong_password, derive_aes_key, encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
from Crypto.PublicKey import RSA

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Tamaño máximo de archivo: 16MB

# Crear carpeta de subidas si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

JSON_FILE_PATH = 'files.json'

# Inicializar la base de datos
with app.app_context():
    db.init_app(app)
    db.create_all()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('upload_page'))
    return redirect(url_for('login'))

""" AUTENTICACIÓN """

@app.route('/login', methods=['GET', 'POST'])
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')

        hashed_password = generate_password_hash(password)

        # Generar el par de claves RSA
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()

        new_user = User(username=username, password=hashed_password, 
                        public_key=public_key, private_key=private_key)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

""" APLICACIÓN DE ENCRIPTACIÓN """

@app.get('/upload')
def upload_page():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))
    
    user_files = get_user_files(JSON_FILE_PATH)
    return render_template('upload.html', files=user_files, username=session['username'])

@app.post('/upload')
def upload_file():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    file = request.files['file']
    password = request.form.get('password')
    user_id = session.get('user_id')
    
    if not file or not password:
        return jsonify({'error': 'File and password are required'}), 400

    if not is_strong_password(password):
        return jsonify({'error': 'Password must be at least 5 characters long'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        filename = secure_filename(file.filename)
        user_filename = f"user_{user_id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
        file.save(file_path)

        # Derivar la clave AES a partir de la contraseña del archivo
        aes_key = derive_aes_key(password)

        # Obtener la clave pública del usuario desde la base de datos
        user = User.query.get(user_id)
        
        # Encriptar la clave AES con RSA
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, user.public_key)

        # Encriptar el archivo
        encrypted_file_path = encrypt_file(file_path, aes_key)
        os.remove(file_path)  # Eliminar el archivo original después de encriptarlo

        # Guardar información en JSON
        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "encrypted_aes_key": encrypted_aes_key,
            "path": encrypted_file_path,
            "user_id": user_id
         })
        save_json(files_data, JSON_FILE_PATH)
            
        return jsonify({
                'message': 'File encrypted and saved successfully',
                'filename': os.path.basename(encrypted_file_path)
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.post('/download')
def download_file():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    path = request.form.get('path')
    user_id = session.get('user_id')

    if not all([path, user_id]):
        return jsonify({'error': 'Missing required information'}), 400
    
    if not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404

    temp_decrypted = None
    try:
        files_data = load_json(JSON_FILE_PATH)
        file_info = next(f for f in files_data['files'] if f['path'] == path and f['user_id'] == user_id)
        
        # Desencriptar la clave AES con la clave privada RSA del usuario
        user = User.query.get(user_id)
        aes_key = decrypt_aes_key_with_rsa(file_info['encrypted_aes_key'], user.private_key)

        # Desencriptar el archivo con la clave AES obtenida
        temp_decrypted = decrypt_file(path, aes_key)

        return send_file(
            temp_decrypted,
            as_attachment=True,
            download_name=path.replace('_encrypted', '').replace(f"user_{user_id}_", "")
        )
    
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
    
    finally:
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)

if __name__ == '__main__':
    app.run(debug=True)
