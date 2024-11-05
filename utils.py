from flask import session
import json
import os
from encriptar import MasterCipher  # Importar clase de encriptación

# Inicializar el cifrador para datos sensibles
cipher = MasterCipher()

def get_user_files(json_record_path):
    """Obtiene la lista de archivos del usuario actual, desencriptando contraseñas de archivos."""
    user_id = session.get('user_id')
    if not user_id:
        return []
    
    files_json = load_json(json_record_path)
    files = files_json["files"]

    user_files = []
    for file in files:
        if file["user_id"] == user_id:
            # Desencriptar la contraseña del archivo antes de agregarla a la lista del usuario
            file["password"] = cipher.decrypt(file["password"])
            user_files.append(file)

    return user_files

def allowed_file(filename):
    """Verifica si la extensión del archivo está permitida."""
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_json(json_path):
    """Función para cargar datos JSON desde un archivo."""
    try:
        with open(json_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {'users': []}

def save_json(data, json_path):
    """Función para guardar datos en un archivo JSON."""
    with open(json_path, 'w') as file:
        json.dump(data, file, indent=4)
