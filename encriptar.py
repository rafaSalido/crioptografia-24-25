import argparse
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Padding

MIN_PASSWORD_LENGTH = 5

class AESCipher:
    
    """Clase que encapsula la lógica de cifrado y descifrado usando AES en modo CBC."""
    
    def __init__(self, password, salt):
        self.key = scrypt(password.encode('utf-8'), salt, 32, N=2**14, r=8, p=1)

    def encrypt(self, data):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = Padding.pad(data, AES.block_size)
        return iv, cipher.encrypt(padded_data)

    def decrypt(self, iv, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return Padding.unpad(decrypted_data, AES.block_size)

def is_strong_password(password):
    
    """Verifica que la contraseña tenga la longitud mínima."""
    
    return len(password) >= MIN_PASSWORD_LENGTH

def get_encrypted_filename(file_path):
    
    """Genera el nombre de archivo para el archivo encriptado, añadiendo '_encrypted' antes de la extensión."""
    
    base, ext = os.path.splitext(file_path)
    return f"{base}_encrypted{ext}"

def get_decrypted_filename(file_path):
    
    """Genera el nombre de archivo para el archivo desencriptado, cambiando '_encrypted' por '_decrypted'."""
    
    if "_encrypted" in file_path:
        return file_path.replace("_encrypted", "_decrypted")
    else:
        base, ext = os.path.splitext(file_path)
        return f"{base}_decrypted{ext}"

def encrypt_file(file_path, password):
    
    """Función para encriptar un archivo dado."""
    
    if not os.path.exists(file_path):
        print(f"Error: El archivo {file_path} no existe.")
        return

    if not is_strong_password(password):
        print(f"La contraseña es demasiado débil. Debe tener al menos {MIN_PASSWORD_LENGTH} caracteres.")
        sys.exit(1)

    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()

        salt = get_random_bytes(16)
        cipher = AESCipher(password, salt)
        iv, ciphertext = cipher.encrypt(file_data)

        encrypted_file_path = get_encrypted_filename(file_path)
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + iv + ciphertext)

        print(f"Archivo encriptado guardado en: {encrypted_file_path}")

    except Exception as e:
        print(f"Error al encriptar el archivo: {e}")
        sys.exit(1)

def decrypt_file(encrypted_file_path, password):
    
    """Función para desencriptar un archivo dado."""
    
    if not os.path.exists(encrypted_file_path):
        print(f"Error: El archivo {encrypted_file_path} no existe.")
        return

    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        cipher = AESCipher(password, salt)
        decrypted_data = cipher.decrypt(iv, ciphertext)

        decrypted_file_path = get_decrypted_filename(encrypted_file_path)
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"Archivo desencriptado guardado en: {decrypted_file_path}")

    except Exception as e:
        print(f"Error al desencriptar el archivo: {e}")
        sys.exit(1)

def handle_compressed_or_file(file_path, password, action):
    
    """Maneja el cifrado o descifrado de archivos y archivos comprimidos."""
    
    compressed_extensions = ['.zip', '.tar', '.gz', '.bz2', '.xz']
    _, file_extension = os.path.splitext(file_path)

    if file_extension in compressed_extensions:
        if action == 'encrypt':
            print(f"El archivo comprimido {file_path} será cifrado.")
            encrypt_file(file_path, password)
        elif action == 'decrypt':
            print(f"El archivo comprimido {file_path} será descifrado.")
            decrypt_file(file_path, password)
    else:
        if action == 'encrypt':
            print(f"El archivo {file_path} (no comprimido) será cifrado.")
            encrypt_file(file_path, password)
        elif action == 'decrypt':
            print(f"El archivo {file_path} (no comprimido) será descifrado.")
            decrypt_file(file_path, password)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encriptar o desencriptar archivos o archivos comprimidos.")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Acción a realizar: 'encrypt' o 'decrypt'.")
    parser.add_argument('file_path', help="Ruta del archivo o archivo comprimido a encriptar/desencriptar.")
    parser.add_argument('password', help="Contraseña para la encriptación/desencriptación.")

    args = parser.parse_args()

    handle_compressed_or_file(args.file_path, args.password, args.action)
