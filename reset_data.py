import os
import json
import shutil
from models import db, User
from main import app  # Importa la instancia de Flask desde tu archivo principal

def reset_data():
    # Limpiar la base de datos de usuarios
    with app.app_context():
        try:
            db.session.query(User).delete()  # Elimina todos los usuarios
            db.session.commit()
            print("Usuarios eliminados de la base de datos.")
        except Exception as e:
            print(f"Error al eliminar usuarios: {e}")

    # Limpiar el archivo files.json
    json_file_path = 'files.json'
    try:
        with open(json_file_path, 'w') as file:
            json.dump({'files': []}, file, indent=4)
            print(f"Archivo {json_file_path} reiniciado.")
    except Exception as e:
        print(f"Error al reiniciar el archivo JSON: {e}")

    # Eliminar todos los archivos en la carpeta de subidas
    uploads_folder = app.config['UPLOAD_FOLDER']
    if os.path.exists(uploads_folder):
        try:
            shutil.rmtree(uploads_folder)  # Borra la carpeta de subidas
            os.makedirs(uploads_folder, exist_ok=True)  # Recrea la carpeta vacía
            print(f"Carpeta {uploads_folder} reiniciada.")
        except Exception as e:
            print(f"Error al eliminar la carpeta de subidas: {e}")

    print("Datos antiguos eliminados correctamente.")

if __name__ == "__main__":
    confirm = input("Este script eliminará todos los usuarios y archivos. ¿Estás seguro? (s/n): ")
    if confirm.lower() == 's':
        reset_data()
    else:
        print("Operación cancelada.")
