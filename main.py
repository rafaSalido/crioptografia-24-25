import base64
from datetime import datetime
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
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash

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

# Rutas para las carpetas json
BASE_JSON_DIR = 'json'
COMMUNITIES_JSON_DIR = os.path.join(BASE_JSON_DIR, 'communities')

# Crear las carpetas si no existen
os.makedirs(COMMUNITIES_JSON_DIR, exist_ok=True)

JSON_FILE_PATH = os.path.join(BASE_JSON_DIR, 'users.json')  # Archivo JSON para almacenar la información de los archivos


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

    # Validar si el usuario ya existe
    if Community.query.filter_by(name=name).first():
        flash('Username already exists', 'error')
        return render_template('signup.html')

    if not name or not password:
        flash('Please fill all the fields', 'error')
        return redirect(url_for('communities_page'))

    hashed_password = generate_password_hash(password)

    public_key, private_key = kyber.keygen()

    # Cifrar la clave privada con la contraseña de la comunidad usando AES
    salt = os.urandom(SALT_LENGTH)
    derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    iv = os.urandom(16)  # Vector de inicialización para AES en modo CBC
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    encrypted_private_key = iv + salt + cipher.encrypt(pad(private_key, AES.block_size))
    # Crear certificado para la comunidad
    certificate = generate_certificate(name, public_key.hex(), is_community=True)
    community = Community(
            name=name,
            password=hashed_password,
            public_key_kyber=public_key.hex(),
            private_key_kyber=base64.b64encode(encrypted_private_key).decode('utf-8'),
            certificate_path=certificate
        )
    
    # Crear la nueva comunidad y almacenar la ruta del certificado
    try:
        db.session.add(community)
        db.session.commit()

        # Asociar el usuario creador a la comunidad
        community_user = CommunityUser(
            user_id=session['user_id'],
            community_id=community.id
        )
        db.session.add(community_user)
        db.session.commit()

        # Crear archivo JSON con la estructura inicial
        community_json = {
            "community_id": community.id,
            "community_name": name,
            "files": []
        }
        json_path = os.path.join(COMMUNITIES_JSON_DIR, f"community_{community.id}_files.json")
        save_json(community_json, json_path)

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

    # Verificar si el usuario ya pertenece a la comunidad
    existing_membership = CommunityUser.query.filter_by(user_id=user.id, community_id=community_id).first()
    if existing_membership:
        flash('You are already a member of this community.', 'info')
        return redirect(url_for('community_page', community_id=community_id))

    # Obtener la contraseña proporcionada por el usuario
    password = request.form.get('password')
    if not password:
        flash('Password is required to join this community.', 'error')
        return redirect(url_for('communities_page'))

    # Verificar si la contraseña proporcionada coincide con la de la comunidad
    if not check_password_hash(community.password, password):
        flash('Incorrect password. Please try again.', 'error')
        return redirect(url_for('communities_page'))

    try:
        # Añadir al usuario a la comunidad
        new_membership = CommunityUser(user_id=user.id, community_id=community_id)
        db.session.add(new_membership)
        db.session.commit()

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

    json_path = os.path.join(COMMUNITIES_JSON_DIR, f"community_{community_id}_files.json")
    community_files_data = load_json(json_path)
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
    
    if not validate_certificate(community.name, is_community=True):
        return jsonify({'error': 'Invalid community certificate'}), 400
    
    try:
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"community_{community_id}_{filename}")
        file.save(file_path)

        public_key = bytes.fromhex(community.public_key_kyber)
        shared_key, ciphertext = kyber.encaps(public_key)

        encrypted_file_path = encrypt_file(file_path, shared_key)
        os.remove(file_path)

        json_path = os.path.join(COMMUNITIES_JSON_DIR, f"community_{community_id}_files.json")
        files_data = load_json(json_path)

        # Agregar el archivo a la lista con la nueva estructura
        file_entry = {
            "file_id": len(files_data['files']) + 1,  # Generar un nuevo ID único
            "name": filename,
            "path": encrypted_file_path,
            "ciphertext": ciphertext.hex(),
            "uploaded_by": {
                "user_id": user.id,
                "username": user.username
            },
            "timestamp": datetime.utcnow().isoformat()  # Fecha actual en formato ISO
        }
        files_data['files'].append(file_entry)

        # Guardar el JSON actualizado
        save_json(files_data, json_path)


        return jsonify({'message': 'File encrypted and saved successfully', 'filename': os.path.basename(encrypted_file_path)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Descargar un archivo y descifrarlo
@app.post('/community/<int:community_id>/download')
def download_community_file(community_id: int):
    file_id = int(request.form.get('file_id'))  # Asegúrate de recibir file_id del formulario
    temp_decrypted = None

    # Obtener información de la comunidad
    community = Community.query.get(community_id)
    if not community:
        return jsonify({'error': 'Community not found'}), 404

    # Validar el usuario autenticado
    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    try:
        # Obtener la contraseña para descifrar la clave privada
        password = request.form.get('password') or request.args.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        # Cargar datos de archivos de la comunidad
        json_path = os.path.join(COMMUNITIES_JSON_DIR, f"community_{community_id}_files.json")
        files_data = load_json(json_path)
        
        # Buscar el archivo por file_id
        file_info = next((f for f in files_data['files'] if f['file_id'] == file_id), None)
        if not file_info:
            return jsonify({'error': 'File information not found'}), 404

        # Obtener la clave privada de la comunidad y descifrarla
        private_key_encrypted = base64.b64decode(community.private_key_kyber)
        iv, salt, ciphertext = private_key_encrypted[:16], private_key_encrypted[16:16 + SALT_LENGTH], private_key_encrypted[16 + SALT_LENGTH:]
        derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        private_key = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Recuperar la clave compartida del archivo
        shared_key = kyber.decaps(private_key, bytes.fromhex(file_info['ciphertext']))

        # Desencriptar el archivo
        temp_decrypted = decrypt_file(file_info['path'], shared_key)

        # Enviar el archivo al cliente
        return send_file(temp_decrypted, as_attachment=True, download_name=file_info['name'])

    except (ValueError, KeyError) as e:
        return jsonify({'error': 'Incorrect password or decryption failed'}), 400

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

    finally:
        # Eliminar el archivo temporal desencriptado
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)


'''
    UPLOAD FEATURE URLS
'''

# Página de subida de archivos
@app.get('/upload')
def upload_page():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('auth.login'))
    
    # Obtener el ID del usuario autenticado desde la sesión
    user_id = session.get('user_id')
    if not user_id:
        flash('User not authenticated.', 'error')
        return redirect(url_for('auth.login'))

    # Filtrar los archivos privados del usuario actual
    user_files = get_user_files(JSON_FILE_PATH, user_id=user_id, is_private=True)

    # Renderizar la página con los archivos filtrados
    return render_template('upload.html', files=user_files, username=session['username'])

# Subir un archivo y cifrarlo
@app.post('/upload')
def upload_file():
    # Verificar si el usuario está autenticado
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Obtener el archivo subido
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file or type'}), 400

    # Obtener los datos del usuario autenticado
    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    # Validar el certificado del usuario antes de permitir la subida
    cert_err = validate_certificate(user.username)  # Verificar la validez del certificado
    if not cert_err:  # Si el certificado no es válido
        return jsonify({'error': 'Invalid certificate, file upload not allowed'}), 403

    try:
        # Si el certificado es válido, continuar con la subida
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user.id}_{filename}")
        file.save(file_path)

        # Encriptar el archivo usando la clave pública del usuario
        public_key = bytes.fromhex(user.public_key_kyber)
        shared_key, ciphertext = kyber.encaps(public_key)

        # Cifrar el archivo
        encrypted_file_path = encrypt_file(file_path, shared_key)
        os.remove(file_path)  # Eliminar el archivo original después de cifrarlo

        # Guardar la información del archivo cifrado en el JSON
        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "ciphertext": ciphertext.hex(),
            "path": encrypted_file_path,
            "user_id": user.id
        })
        save_json(files_data, JSON_FILE_PATH)

        # Log de éxito
        logger.info(f"Archivo {filename} encriptado y guardado correctamente para el usuario {user.username}")
        return jsonify({'message': 'File encrypted and saved successfully', 'filename': os.path.basename(encrypted_file_path)})

    except Exception as e:
        # Manejo de excepciones
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
