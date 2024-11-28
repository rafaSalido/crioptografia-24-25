from base64 import b64decode
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from Crypto.Cipher import AES
import logging
from auth import auth_blueprint
from utils import allowed_file, get_user_files, load_json, save_json
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

kyber = Kyber512  # Inicializar Kyber512 para operaciones de encriptación
JSON_FILE_PATH = 'files.json'  # Archivo JSON para almacenar la información de los archivos

# Obtener el usuario autenticado desde la sesión
def get_authenticated_user():
    user_id = session.get('user_id')
    if not user_id:
        return None, jsonify({'error': 'Not authenticated'}), 401  # Error si el usuario no está autenticado
    user = User.query.get(user_id)
    if not user:
        logger.error("Usuario no encontrado en la base de datos")
        return None, jsonify({'error': 'User not found'}), 404  # Error si el usuario no está en la base de datos
    return user, None, None

# Ruta principal que redirige según la autenticación
@app.route('/')
def home():
    return redirect(url_for('upload_page') if 'username' in session else url_for('auth.login'))

'''
    COMMUNITY FEATURE URLS
'''

# Página de comunidades
@app.get('/communities')
def communities_page():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')  # Mensaje de error si no está autenticado
        return redirect(url_for('auth.login'))  # Redirigir al login

    user_communities = Community.query.join(CommunityUser).filter(CommunityUser.user_id == session['user_id']).all()
    user_communities_ids = [community.id for community in user_communities]

    # Filtrar las comunidades que no pertenecen al usuario
    other_communities = Community.query.filter(~Community.id.in_(user_communities_ids)).all()

    return render_template('communities.html', user_communities=user_communities, other_communities=other_communities, username=session['username'])


# Crear una comunidad
@app.post('/create-community')
def create_community():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('auth.login'))

    name = request.form.get('name')
    password = request.form.get('password')

    if not name or not password:
        flash('Please fill all the fields', 'error')
        return redirect(url_for('communities_page'))
    
    encrypted_password = generate_password_hash(password)

    # Generar un certificado para la comunidad
    try:
        certificate_path = generate_certificate(name, APP_PUBLIC_KEY.hex(), is_community=True)
    except Exception as e:
        flash(f"Error al generar el certificado para la comunidad: {str(e)}", 'error')
        return redirect(url_for('communities_page'))

    # Crear la nueva comunidad y almacenar la ruta del certificado
    try:
        community = Community(
            name=name,
            password=encrypted_password,
            certificate_path=certificate_path  # Guardar la ruta del certificado en lugar del contenido
        )
        db.session.add(community)
        db.session.commit()

        # Asociar el usuario creador a la comunidad
        community_user = CommunityUser(
            user_id=session['user_id'],
            community_id=community.id
        )
        db.session.add(community_user)
        db.session.commit()

        return redirect(url_for('community_page', community_id=community.id))
    except Exception as e:
        db.session.rollback()  # Revertir cambios en caso de error
        flash(f"Error al crear la comunidad: {str(e)}", 'error')
        return redirect(url_for('communities_page'))

@app.post('/join-community/<int:community_id>')
def join_community(community_id):
    if 'username' not in session:
        flash('Please log in to join a community.', 'error')
        return redirect(url_for('auth.login'))

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    community = Community.query.get(community_id)
    if not community:
        flash('Community not found.', 'error')
        return redirect(url_for('communities_page'))

    existing_membership = CommunityUser.query.filter_by(user_id=user.id, community_id=community_id).first()
    if existing_membership:
        flash('You are already a member of this community.', 'info')
        return redirect(url_for('community_page', community_id=community_id))

    try:
        new_membership = CommunityUser(user_id=user.id, community_id=community_id)
        db.session.add(new_membership)
        db.session.commit()

        # Actualizar los archivos existentes para incluir al nuevo miembro
        json_filename = f"community_{community_id}_files.json"
        community_files_data = load_json(json_filename)

        for file_info in community_files_data.get("files", []):
            encrypted_keys = file_info.get("encrypted_aes_keys", {})
            if str(user.id) not in encrypted_keys:
                public_key = bytes.fromhex(user.public_key_kyber)
                aes_key = b64decode(encrypted_keys[next(iter(encrypted_keys))])
                encrypted_key_for_new_member = encrypt_aes_key_with_kyber(aes_key, public_key.hex())
                encrypted_keys[str(user.id)] = encrypted_key_for_new_member
                file_info["encrypted_aes_keys"] = encrypted_keys

        save_json(community_files_data, json_filename)

        flash('You have successfully joined the community and have been given access to all community files.', 'success')
        return redirect(url_for('community_page', community_id=community_id))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding user to community: {str(e)}")
        flash('An error occurred while trying to join the community.', 'error')
        return redirect(url_for('communities_page'))

# Página de comunidad con sus archivos
@app.get('/community/<int:community_id>')
def community_page(community_id):
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('auth.login'))

    community = Community.query.get(community_id)
    if not community:
        flash('Community not found', 'error')
        return redirect(url_for('communities_page'))

    json_filename = f"community_{community_id}_files.json"
    community_files_data = load_json(json_filename)
    community_files = community_files_data.get("files", [])

    return render_template('community.html', community=community, files=community_files, username=session['username'])

# Subir archivo a una comunidad
@app.post('/upload-to-community/<int:community_id>')
def upload_to_community(community_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file or type'}), 400

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    community_user = CommunityUser.query.filter_by(user_id=user.id, community_id=community_id).first()
    if not community_user:
        return jsonify({'error': 'Not a member of this community'}), 403

    community = Community.query.get(community_id)
    if not community or not community.certificate_path:
        return jsonify({'error': 'Community certificate not found'}), 404

    try:
        if not validate_certificate(community.name, is_community=True):
            logger.warning(f"Certificado de la comunidad {community.name} no es válido.")
            return jsonify({'error': 'Invalid community certificate'}), 400
    except Exception as e:
        logger.error(f"Error al validar el certificado de la comunidad: {str(e)}")
        return jsonify({'error': 'Community certificate validation failed'}), 500

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"community_{community_id}_{filename}")
        file.save(file_path)

        aes_key = get_random_bytes(KEY_LENGTH)
        encrypted_file_path = encrypt_file(file_path, aes_key)
        os.remove(file_path)

        encrypted_keys = {}
        members = CommunityUser.query.filter_by(community_id=community_id).all()
        for member in members:
            member_user = User.query.get(member.user_id)
            if not member_user.public_key_kyber:
                logger.error(f"Usuario {member_user.id} no tiene una clave pública configurada.")
                continue  # Saltar usuarios sin clave pública

            try:
                public_key = bytes.fromhex(member_user.public_key_kyber)
                encrypted_key = encrypt_aes_key_with_kyber(aes_key, public_key.hex())
                encrypted_keys[str(member_user.id)] = encrypted_key
            except ValueError as e:
                logger.error(f"Error al procesar la clave pública del usuario {member_user.id}: {str(e)}")

        json_filename = f"community_{community_id}_files.json"
        community_files_data = load_json(json_filename)

        community_files_data.setdefault("files", []).append({
            "name": filename,
            "path": encrypted_file_path,
            "encrypted_aes_keys": encrypted_keys
        })

        save_json(community_files_data, json_filename)

        logger.info(f"Archivo {filename} encriptado y guardado correctamente para la comunidad {community_id}")
        return jsonify({'message': 'File encrypted and saved successfully', 'filename': os.path.basename(encrypted_file_path)})

    except Exception as e:
        logger.error(f"Error al encriptar el archivo: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

    is_community_file = "community_" in path
    temp_decrypted = None

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    try:
        if not is_community_file:
            password = request.form.get('password') or request.args.get('password')
            if not password:
                logger.error("La contraseña es requerida para descifrar la clave privada.")
                return jsonify({'error': 'Password is required'}), 400

            files_data = load_json(JSON_FILE_PATH)
            file_info = next((f for f in files_data['files'] if f['path'] == path and f['user_id'] == user.id), None)
            if not file_info:
                return jsonify({'error': 'File information not found'}), 404

            private_key_encrypted = b64decode(user.private_key_kyber)
            iv, salt, ciphertext = private_key_encrypted[:16], private_key_encrypted[16:16 + SALT_LENGTH], private_key_encrypted[16 + SALT_LENGTH:]
            derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            cipher = AES.new(derived_key, AES.MODE_CBC, iv)
            private_key = unpad(cipher.decrypt(ciphertext), AES.block_size)

            shared_key = kyber.decaps(private_key, bytes.fromhex(file_info['ciphertext']))
            temp_decrypted = decrypt_file(path, shared_key)

            logger.info(f"Archivo {file_info['name']} desencriptado correctamente para el usuario {user.username}")
            return send_file(temp_decrypted, as_attachment=True, download_name=os.path.basename(path).replace('_encrypted', ''))

        else:
            json_filename = f"community_{path.split('_')[1]}_files.json"
            community_files_data = load_json(json_filename)
            file_info = next((f for f in community_files_data['files'] if f['path'] == path), None)
            if not file_info:
                return jsonify({'error': 'Community file information not found'}), 404

            encrypted_keys = file_info.get("encrypted_aes_keys", {})
            encrypted_aes_key = encrypted_keys.get(str(user.id))

            if not encrypted_aes_key:
                logger.error(f"El usuario {user.id} no tiene una clave AES asignada para este archivo.")
                return jsonify({'error': 'User does not have access to this file'}), 403

            try:
                aes_key = decrypt_aes_key_with_kyber(encrypted_aes_key, user.private_key_kyber)
            except ValueError as e:
                logger.error(f"Error al descifrar la clave AES del archivo para el usuario {user.id}: {str(e)}")
                return jsonify({'error': 'Decryption of AES key failed'}), 400

            try:
                aes_key = decrypt_aes_key_with_kyber(encrypted_aes_key, user.private_key_kyber)
            except Exception as e:
                logger.error(f"Error durante el descifrado de la clave AES para el archivo comunitario: {str(e)}")
                return jsonify({'error': 'Decryption of AES key failed'}), 400

            try:
                temp_decrypted = decrypt_file(path, aes_key)
            except Exception as e:
                logger.error(f"Error durante el descifrado del archivo comunitario: {str(e)}")
                return jsonify({'error': 'Decryption of file failed'}), 400

            logger.info(f"Archivo comunitario {file_info['name']} desencriptado correctamente para el usuario {user.username}")
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
