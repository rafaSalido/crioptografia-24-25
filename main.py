import base64
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from Crypto.Cipher import AES
import logging
from auth import auth_blueprint
from communities.communities_blueprint import communities_blueprint
from utils import allowed_file, get_authenticated_user, get_user_files, load_json, save_json
from db import db
from auth.models import Community, CommunityFiles, CommunityUser, User
from encrypt import decrypt_aes_key_with_kyber, encrypt_aes_key_with_kyber, encrypt_file, decrypt_file, encrypt_with_master_key, decrypt_with_master_key
from kyber.kyber import Kyber512
from auth.certificate import APP_PUBLIC_KEY, generate_certificate, validate_certificate, KEY_LENGTH, SALT_LENGTH, SCRYPT_N, SCRYPT_P, SCRYPT_R
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# Configurar logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Clave secreta para la aplicación Flask
MASTER_KEY = os.getenv('ENCRYPTION_KEY').encode('utf-8')  # Clave maestra para la encriptación

# Configuración de la base de datos y almacenamiento
app.config.update({
    'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URI'),  # URL de la base de datos
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,  # Desactivar el seguimiento de modificaciones
    'UPLOAD_FOLDER': os.getenv('UPLOAD_FOLDER'),  # Carpeta para almacenar los archivos subidos
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024  # Tamaño máximo de archivo: 16MB
})
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Crear la carpeta de subidas si no existe

# Inicializar la base de datos
with app.app_context():
    db.init_app(app)  # Inicializar la base de datos
    db.create_all()  # Crear las tablas necesarias en la base de datos

# Registrar el blueprint de autenticación
app.register_blueprint(auth_blueprint, url_prefix='/auth')
app.register_blueprint(communities_blueprint, url_prefix='/communities')

kyber = Kyber512  # Inicializar Kyber512 para operaciones de encriptación
JSON_FILE_PATH = 'files.json'  # Archivo JSON para almacenar la información de los archivos



# Ruta principal que redirige según la autenticación
@app.route('/')
def home():
    return redirect(url_for('upload_page') if 'username' in session else url_for('auth.login'))


'''
    UPLOAD FEATURE URLS
'''

# Página de subida de archivos
@app.get('/upload')
def upload_page():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('auth.login'))
    user_files = get_user_files(JSON_FILE_PATH)
    return render_template('upload.html', files=user_files, username=session['username'])

# Subir un archivo y cifrarlo
@app.post('/upload')
def upload_file():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file or type'}), 400

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    cert_err = validate_certificate(user)
    if cert_err:
        return cert_err

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user.id}_{filename}")
        file.save(file_path)

        public_key = bytes.fromhex(user.public_key_kyber)
        shared_key, ciphertext = kyber.encaps(public_key)

        encrypted_file_path = encrypt_file(file_path, shared_key)
        os.remove(file_path)

        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "ciphertext": ciphertext.hex(),
            "path": encrypted_file_path,
            "user_id": user.id
        })
        save_json(files_data, JSON_FILE_PATH)

        logger.info(f"Archivo {filename} encriptado y guardado correctamente para el usuario {user.username}")
        return jsonify({'message': 'File encrypted and saved successfully', 'filename': os.path.basename(encrypted_file_path)})

    except Exception as e:
        logger.error(f"Error al encriptar el archivo: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Descargar un archivo y descifrarlo
@app.post('/download')
def download_file():
    path = request.form.get('path')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404

    temp_decrypted = None

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    try:
        password = request.form.get('password') or request.args.get('password')
        if not password:
            logger.error("La contraseña es requerida para descifrar la clave privada.")
            return jsonify({'error': 'Password is required'}), 400

        files_data = load_json(JSON_FILE_PATH)
        file_info = next((f for f in files_data['files'] if f['path'] == path and f['user_id'] == user.id), None)
        if not file_info:
            return jsonify({'error': 'File information not found'}), 404

        private_key_encrypted = base64.b64decode(user.private_key_kyber)
        iv, salt, ciphertext = private_key_encrypted[:16], private_key_encrypted[16:16 + SALT_LENGTH], private_key_encrypted[16 + SALT_LENGTH:]
        derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        private_key = unpad(cipher.decrypt(ciphertext), AES.block_size)

        shared_key = kyber.decaps(private_key, bytes.fromhex(file_info['ciphertext']))
        temp_decrypted = decrypt_file(path, shared_key)

        logger.info(f"Archivo {file_info['name']} desencriptado correctamente para el usuario {user.username}")
        return send_file(temp_decrypted, as_attachment=True, download_name=os.path.basename(path).replace('_encrypted', ''))


    except (ValueError, KeyError) as e:
        logger.error(f"Error durante el descifrado: {str(e)}")
        return jsonify({'error': 'Incorrect password or decryption failed'}), 400

    except Exception as e:
        logger.error(f"Error durante la descarga del archivo: {str(e)}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

    finally:
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)

if __name__ == '__main__':
    app.run(debug=True)
