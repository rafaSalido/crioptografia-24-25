from flask import session
import json
import os
import logging
from encrypt import MasterCipher  # Importar clase de encriptación
from json.decoder import JSONDecodeError

# Configurar logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Inicializar el cifrador para datos sensibles
cipher = MasterCipher()

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}

def get_user_files(json_record_path, user_id=None, is_private=False):
    """
    Obtiene la lista de archivos asociados al usuario actual o a una comunidad específica.

    :param json_record_path: Ruta al archivo JSON con los registros de archivos.
    :param user_id: ID del usuario para filtrar archivos. Si es None, retorna todos los archivos.
    :return: Lista de archivos.
    """
    # Cargar los datos del JSON
    files_json = load_json(json_record_path)
    
    if is_private:
        # Filtrar archivos privados del usuario actual
        return [
            file for file in files_json.get("files", [])
            if file.get("user_id") == user_id
        ]

    # Si no es privado, retornar todos los archivos
    return files_json.get("files", [])


def allowed_file(filename):
    """
    Verifica si un archivo tiene una extensión permitida.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_json(json_path):
    """
    Carga datos desde un archivo JSON.
    Si el archivo no existe o está corrupto, retorna un JSON vacío.
    """
    try:
        with open(json_path, 'r') as file:
            data = json.load(file)
            logger.debug(f"Archivo JSON cargado correctamente desde: {json_path}")
            return data
    except FileNotFoundError:
        logger.warning(f"Archivo JSON no encontrado: {json_path}. Creando uno nuevo.")
        return {'files': []}
    except JSONDecodeError:
        logger.error(f"Archivo JSON corrupto: {json_path}. Creando uno nuevo.")
        return {'files': []}
    except Exception as e:
        logger.error(f"Error al cargar el archivo JSON: {e}. Retornando JSON vacío.")
        return {'files': []}

def save_json(data, json_path):
    """
    Guarda datos en un archivo JSON de manera segura.
    """
    try:
        # Guardar los datos en un archivo temporal primero para evitar corrupción si falla el proceso.
        temp_json_path = json_path + '.tmp'
        with open(temp_json_path, 'w') as file:
            json.dump(data, file, indent=4)
            logger.debug(f"Datos guardados temporalmente en {temp_json_path}")

        # Renombrar el archivo temporal al nombre del archivo real.
        os.replace(temp_json_path, json_path)
        logger.info(f"Datos guardados correctamente en {json_path}")

    except Exception as e:
        logger.error(f"Error guardando datos en {json_path}: {e}")

# Opcional: Agregar una función para cifrar y descifrar el JSON, si fuera necesario
def save_json_encrypted(data, json_path):
    """
    Cifra y guarda datos en un archivo JSON.
    """
    try:
        encrypted_data = cipher.encrypt(json.dumps(data))
        temp_json_path = json_path + '.tmp'
        with open(temp_json_path, 'w') as file:
            file.write(encrypted_data)
        os.replace(temp_json_path, json_path)
        logger.info(f"Datos encriptados y guardados correctamente en {json_path}")
    except Exception as e:
        logger.error(f"Error guardando datos en {json_path}: {e}")

def load_json_encrypted(json_path):
    """
    Descifra y carga datos desde un archivo JSON encriptado.
    Si el archivo no existe o está corrupto, retorna un JSON vacío.
    """
    try:
        with open(json_path, 'r') as file:
            encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    except FileNotFoundError:
        logger.warning(f"Archivo JSON encriptado no encontrado: {json_path}. Creando uno nuevo.")
        return {'files': []}
    except (JSONDecodeError, ValueError) as e:
        logger.error(f"Archivo JSON encriptado corrupto o error en descifrado: {e}. Creando uno nuevo.")
        return {'files': []}
    except Exception as e:
        logger.error(f"Error al cargar el archivo JSON encriptado: {e}. Retornando JSON vacío.")
        return {'files': []}