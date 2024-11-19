import os
import json
import shutil
from models import db, User
from main import app  # Importa la instancia de Flask desde tu archivo principal

def reset_data():
    """
    Elimina todos los datos de usuarios, archivos en JSON y los archivos subidos.
    """
    def log_message(message):
        print(f"[RESET DATA] {message}")

    # Limpiar la base de datos de usuarios
    with app.app_context():
        try:
            db.session.query(User).delete()
            db.session.commit()
            log_message("Usuarios eliminados de la base de datos.")
        except Exception as e:
            db.session.rollback()
            log_message(f"Error al eliminar usuarios: {e}")

    # Reiniciar el archivo files.json
    json_file_path = 'files.json'
    try:
        if not os.path.exists(json_file_path):
            log_message(f"El archivo {json_file_path} no existe. Será creado.")
        with open(json_file_path, 'w') as file:
            json.dump({'files': []}, file, indent=4)
            log_message(f"Archivo {json_file_path} reiniciado.")
    except Exception as e:
        log_message(f"Error al reiniciar el archivo JSON: {e}")

    # Eliminar todos los archivos en la carpeta de subidas
    uploads_folder = app.config['UPLOAD_FOLDER']
    if os.path.exists(uploads_folder):
        try:
            if not os.access(uploads_folder, os.W_OK):
                log_message(f"No se tienen permisos de escritura en {uploads_folder}.")
                return
            shutil.rmtree(uploads_folder)
            os.makedirs(uploads_folder, exist_ok=True)
            log_message(f"Carpeta {uploads_folder} reiniciada.")
        except Exception as e:
            log_message(f"Error al eliminar la carpeta de subidas: {e}")

    log_message("Datos antiguos eliminados correctamente.")

if __name__ == "__main__":
    confirm = input("Este script eliminará todos los usuarios, archivos JSON y los archivos subidos. Esta acción no puede deshacerse. ¿Estás seguro? (s/n): ")
    if confirm.lower() == 's':
        reset_data()
    else:
        print("Operación cancelada.")
