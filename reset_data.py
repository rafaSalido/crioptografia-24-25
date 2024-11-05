import os
import json
import shutil
from models import db, User
from main import app  # Importa la instancia de Flask desde tu archivo principal

# Limpiar la base de datos de usuarios
with app.app_context():
    db.session.query(User).delete()  # Elimina todos los usuarios
    db.session.commit()
    print("Usuarios eliminados de la base de datos.")

# Limpiar el archivo files.json
json_file_path = 'files.json'
with open(json_file_path, 'w') as file:
    json.dump({'files': []}, file, indent=4)
    print(f"Archivo {json_file_path} reiniciado.")

# Eliminar todos los archivos en la carpeta de subidas
uploads_folder = app.config['UPLOAD_FOLDER']
if os.path.exists(uploads_folder):
    shutil.rmtree(uploads_folder)  # Borra la carpeta de subidas
    os.makedirs(uploads_folder, exist_ok=True)  # Recrea la carpeta vacía
    print(f"Carpeta {uploads_folder} reiniciada.")

print("Datos antiguos eliminados correctamente.")
