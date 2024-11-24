from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import json
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from Crypto.Random import get_random_bytes

from auth import auth_blueprint
from utils import allowed_file, get_user_files, load_json, save_json
from db import db
from auth.models import User
from encrypt import encrypt_file, decrypt_file, encrypt_with_master_key, decrypt_with_master_key
from kyber_py.src.kyber_py.kyber import Kyber512

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
MASTER_KEY = os.getenv('ENCRYPTION_KEY').encode('utf-8')

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Tamaño máximo de archivo: 16MB

# Crear carpeta de subidas si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

kyber = Kyber512  # Inicializar Kyber512 globalmente
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

app.register_blueprint(auth_blueprint, url_prefix='/auth')

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
    user_id = session.get('user_id')

    if not file:
        return jsonify({'error': 'File is required'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}_{filename}")
        file.save(file_path)

        # Obtener la clave pública del usuario
        user = User.query.get(user_id)
        public_key = bytes.fromhex(user.public_key_kyber)

        # Realizar encapsulación para obtener la clave AES y el ciphertext
        shared_key, ciphertext = kyber.encaps(public_key)

        # Encriptar el archivo usando la clave compartida generada (shared_key)
        encrypted_file_path = encrypt_file(file_path, shared_key)

        # Eliminar el archivo original después de encriptarlo
        os.remove(file_path)

        # Guardar el ciphertext y la ruta del archivo cifrado en JSON
        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "ciphertext": ciphertext.hex(),
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

    if not path or not user_id:
        return jsonify({'error': 'Missing required information'}), 400

    if not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404

    temp_decrypted = None
    try:
        # Obtener información del archivo
        files_data = load_json(JSON_FILE_PATH)
        file_info = next(f for f in files_data['files'] if f['path'] == path and f['user_id'] == user_id)

        # Recuperar el usuario y descifrar la clave privada
        user = User.query.get(user_id)
        private_key = decrypt_with_master_key(user.private_key_kyber, MASTER_KEY)

        # Recuperar la clave compartida usando Kyber512
        ciphertext = bytes.fromhex(file_info['ciphertext'])
        shared_key = kyber.decaps(private_key, ciphertext)

        # Desencriptar el archivo
        temp_decrypted = decrypt_file(path, shared_key)

        return send_file(
            temp_decrypted,
            as_attachment=True,
            download_name=os.path.basename(path).replace('_encrypted', '')
        )

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
    finally:
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)


if __name__ == '__main__':
    app.run(debug=True)
