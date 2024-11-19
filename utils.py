from flask import session
import json
import os
import logging
from encriptar import MasterCipher  # Importar clase de encriptación

# Configurar logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Inicializar el cifrador para datos sensibles
cipher = MasterCipher()

def get_user_files(json_record_path):
    """
    Obtiene la lista de archivos asociados con el usuario actual.
    """
    user_id = session.get('user_id')
    if not user_id:
        return []
    
    files_json = load_json(json_record_path)
    return [file for file in files_json.get("files", []) if file["user_id"] == user_id]


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}

def allowed_file(filename):
    """
    Verifica si un archivo tiene una extensión permitida.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_json(json_path):
    """
    Carga datos desde un archivo JSON.
    Si el archivo no existe, retorna un JSON vacío.
    """
    try:
        with open(json_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.warning(f"Archivo JSON no encontrado: {json_path}. Creando uno nuevo.")
        return {'files': []}

def save_json(data, json_path):
    """
    Guarda datos en un archivo JSON.
    """
    try:
        with open(json_path, 'w') as file:
            json.dump(data, file, indent=4)
        logger.info(f"Datos guardados en {json_path}")
    except Exception as e:
        logger.error(f"Error guardando datos en {json_path}: {e}")
