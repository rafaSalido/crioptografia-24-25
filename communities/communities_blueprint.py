
import base64
from hashlib import scrypt
import os
from flask import Blueprint, app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from Crypto.Cipher import AES
from auth.certificate import APP_PUBLIC_KEY, KEY_LENGTH, generate_certificate, validate_certificate
from auth.models import Community, CommunityUser
import db
from encrypt import SALT_LENGTH, SCRYPT_N, SCRYPT_P, SCRYPT_R, decrypt_aes_key_with_kyber, decrypt_file, encrypt_aes_key_with_kyber, encrypt_file
from Crypto.Random import get_random_bytes
from kyber.kyber import kyber
from utils import get_authenticated_user
from utils import allowed_file, load_json, save_json
from Crypto.Util.Padding import pad, unpad

communities_blueprint = Blueprint('communities', __name__)

JSON_FILE_PATH = 'communities_files.json'  # Archivo JSON para almacenar la información de los archivos


# Página de comunidades
@communities_blueprint.get('/')
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
@communities_blueprint.post('/create-community')
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

    # Cifrar la clave privada con la contraseña del usuario usando AES
    salt = os.urandom(SALT_LENGTH)
    derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    iv = os.urandom(16)  # Vector de inicialización para AES en modo CBC
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    encrypted_private_key = iv + salt + cipher.encrypt(pad(private_key, AES.block_size))
    # Crear certificado para el usuario
    certificate = generate_certificate(name, public_key.hex())
    community = Community(
            name=name,
            password=hashed_password,
            public_key_kyber=public_key.hex(),
            private_key_kyber=base64.b64encode(encrypted_private_key).decode('utf-8'),
            certificate_dilithium=certificate
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

        return redirect(url_for('community_page', community_id=community.id))
    except Exception as e:
        db.session.rollback()  # Revertir cambios en caso de error
        flash(f"Error al crear la comunidad: {str(e)}", 'error')
        return redirect(url_for('communities_page'))


@communities_blueprint.post('/join-community/<int:community_id>')
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
                aes_key = base64.b64decode(encrypted_keys[next(iter(encrypted_keys))])
                encrypted_key_for_new_member = encrypt_aes_key_with_kyber(aes_key, public_key.hex())
                encrypted_keys[str(user.id)] = encrypted_key_for_new_member
                file_info["encrypted_aes_keys"] = encrypted_keys

        save_json(community_files_data, json_filename)

        flash('You have successfully joined the community and have been given access to all community files.', 'success')
        return redirect(url_for('community_page', community_id=community_id))

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while trying to join the community.', 'error')
        return redirect(url_for('communities_page'))

# Página de comunidad con sus archivos
@communities_blueprint.get('/community/<int:community_id>')
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
@communities_blueprint.post('/upload/<int:community_id>')
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

        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "ciphertext": ciphertext.hex(),
            "path": encrypted_file_path,
            "community_id": community.id
        })
        save_json(files_data, JSON_FILE_PATH)

        return jsonify({'message': 'File encrypted and saved successfully', 'filename': os.path.basename(encrypted_file_path)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    



# Descargar un archivo y descifrarlo
@communities_blueprint.post('/download/<int:community_id>/')
def download_community_file(community_id: int):
    path = request.form.get('path')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404

    temp_decrypted = None

    community = Community.query.get(community_id)

    user, err_response, status = get_authenticated_user()
    if err_response:
        return err_response, status

    try:
        password = request.form.get('password') or request.args.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        files_data = load_json(JSON_FILE_PATH)
        file_info = next((f for f in files_data['files'] if f['path'] == path and f['community_id'] == community.id), None)
        if not file_info:
            return jsonify({'error': 'File information not found'}), 404

        private_key_encrypted = base64.b64decode(user.private_key_kyber)
        iv, salt, ciphertext = private_key_encrypted[:16], private_key_encrypted[16:16 + SALT_LENGTH], private_key_encrypted[16 + SALT_LENGTH:]
        derived_key = scrypt(password.encode('utf-8'), salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        private_key = unpad(cipher.decrypt(ciphertext), AES.block_size)

        shared_key = kyber.decaps(private_key, bytes.fromhex(file_info['ciphertext']))
        temp_decrypted = decrypt_file(path, shared_key)
        
        return send_file(temp_decrypted, as_attachment=True, download_name=os.path.basename(path).replace('_encrypted', ''))

    except (ValueError, KeyError) as e:
        return jsonify({'error': 'Incorrect password or decryption failed'}), 400

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

    finally:
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)