import os
import logging
from typing import Optional, Tuple, Union
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Padding
from base64 import b64encode, b64decode
from dotenv import load_dotenv

# Cargar variables de entorno y configurar logging
load_dotenv()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Clave maestra desde .env para encriptación de datos sensibles
MASTER_KEY = os.getenv('ENCRYPTION_KEY').encode('utf-8')

# Constantes
MIN_PASSWORD_LENGTH = 5
SALT_LENGTH = 16
IV_LENGTH = 16
KEY_LENGTH = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

### SECCIÓN 1: Encriptación de Archivos del Usuario ###

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

class AESCipher:
    """Class that handles AES encryption and decryption in CBC mode with proper error handling."""
    
    def __init__(self, password: str, salt: bytes):
        try:
            self.key = scrypt(
                password=password.encode('utf-8'),
                salt=salt,
                key_len=KEY_LENGTH,
                N=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P
            )
        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise EncryptionError("Failed to initialize encryption")

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        iv = get_random_bytes(IV_LENGTH)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = Padding.pad(data, AES.block_size)
        return iv, cipher.encrypt(padded_data)

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return Padding.unpad(decrypted_data, AES.block_size)

def encrypt_file(file_path: str, password: str) -> Optional[str]:
    if not os.path.exists(file_path) or not is_strong_password(password):
        logger.error("File not found or weak password")
        return None

    with open(file_path, 'rb') as file:
        file_data = file.read()

    salt = get_random_bytes(SALT_LENGTH)
    cipher = AESCipher(password, salt)
    iv, ciphertext = cipher.encrypt(file_data)
    
    encrypted_file_path = get_encrypted_filename(file_path)
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)

    logger.debug(f"File encrypted successfully: {encrypted_file_path}")
    return encrypted_file_path

def decrypt_file(encrypted_file_path: str, password: str) -> Optional[str]:
    if not os.path.exists(encrypted_file_path) or not is_strong_password(password):
        logger.error("File not found or weak password")
        return None

    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    salt = encrypted_data[:SALT_LENGTH]
    iv = encrypted_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = encrypted_data[SALT_LENGTH + IV_LENGTH:]

    cipher = AESCipher(password, salt)
    decrypted_data = cipher.decrypt(iv, ciphertext)

    decrypted_file_path = get_decrypted_filename(encrypted_file_path)
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    logger.debug(f"File decrypted successfully: {decrypted_file_path}")
    return decrypted_file_path

### SECCIÓN 2: Encriptación de Datos sensibles del Backend ###

class MasterCipher:
    """Class to encrypt and decrypt sensitive backend data using a master key."""
    
    def __init__(self, key: bytes = MASTER_KEY):
        self.key = key

    def encrypt(self, data: str) -> str:
        salt = get_random_bytes(SALT_LENGTH)
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        decoded_data = b64decode(encrypted_data)
        salt, nonce, tag, ciphertext = decoded_data[:SALT_LENGTH], decoded_data[SALT_LENGTH:SALT_LENGTH+16], decoded_data[SALT_LENGTH+16:SALT_LENGTH+32], decoded_data[SALT_LENGTH+32:]
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def is_strong_password(password: str) -> bool:
    return isinstance(password, str) and len(password) >= MIN_PASSWORD_LENGTH


### SECCIÓN 3: Asignacion de nombres encriptados/desencriptados ###
def get_encrypted_filename(file_path: str) -> str:
    """
    Genera un nombre de archivo encriptado.

    Args:
        file_path: Ruta original del archivo

    Returns:
        Nombre del archivo con el sufijo '_encrypted'
    """
    base, ext = os.path.splitext(file_path)
    return f"{base}_encrypted{ext}"

def get_decrypted_filename(file_path: str) -> str:
    """
    Genera un nombre de archivo desencriptado.

    Args:
        file_path: Ruta del archivo encriptado

    Returns:
        Nombre del archivo con el sufijo '_decrypted'
    """
    if "_encrypted" in file_path:
        return file_path.replace("_encrypted", "_decrypted")
    base, ext = os.path.splitext(file_path)
    return f"{base}_decrypted{ext}"