import os
import logging
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Padding
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from dotenv import load_dotenv
from kyber.kyber import Kyber512  # Importar Kyber512 correctamente

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

### Encriptación y Desencriptación de Claves AES usando Kyber512 ###

def encrypt_aes_key_with_kyber(aes_key: bytes, public_key_hex: str) -> str:
    kyber = Kyber512
    public_key = bytes.fromhex(public_key_hex)
    _, ciphertext = kyber.encaps(public_key)
    return b64encode(ciphertext).decode('utf-8')

def decrypt_aes_key_with_kyber(ciphertext_b64: str, private_key_hex: str) -> bytes:
    """
    Decapsula el ciphertext para recuperar la clave AES utilizando la clave privada Kyber512.
    """
    kyber = Kyber512
    private_key = bytes.fromhex(private_key_hex)
    ciphertext = b64decode(ciphertext_b64)

    # Recuperar la clave compartida
    shared_key = kyber.decaps(private_key, ciphertext)
    return shared_key

### SECCIÓN 1: Encriptación de Archivos del Usuario ###

class EncryptionError(Exception):
    pass

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        iv = get_random_bytes(IV_LENGTH)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = Padding.pad(data, AES.block_size)
        return iv, cipher.encrypt(padded_data)

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return Padding.unpad(decrypted_data, AES.block_size)

def encrypt_file(file_path: str, aes_key: bytes) -> Optional[str]:
    if not os.path.exists(file_path):
        logger.error("File not found")
        return None

    with open(file_path, 'rb') as file:
        file_data = file.read()

    cipher = AESCipher(aes_key)
    iv, ciphertext = cipher.encrypt(file_data)
    
    encrypted_file_path = get_encrypted_filename(file_path)
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)

    logger.debug(f"File encrypted successfully: {encrypted_file_path}")
    return encrypted_file_path

def decrypt_file(encrypted_file_path: str, aes_key: bytes) -> Optional[str]:
    if not os.path.exists(encrypted_file_path):
        logger.error("File not found")
        return None

    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    iv = encrypted_data[:IV_LENGTH]
    ciphertext = encrypted_data[IV_LENGTH:]

    cipher = AESCipher(aes_key)
    decrypted_data = cipher.decrypt(iv, ciphertext)

    decrypted_file_path = get_decrypted_filename(encrypted_file_path)
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    logger.debug(f"File decrypted successfully: {decrypted_file_path}")
    return decrypted_file_path

### SECCIÓN 2: Encriptación de Datos Sensibles del Backend ###

class MasterCipher:
    def __init__(self, key: bytes = MASTER_KEY):
        self.key = key

    def encrypt(self, data: str) -> str:
        salt = get_random_bytes(SALT_LENGTH)
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=8, p=1)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        decoded_data = b64decode(encrypted_data)
        salt, nonce, tag, ciphertext = (
            decoded_data[:SALT_LENGTH], 
            decoded_data[SALT_LENGTH:SALT_LENGTH+16], 
            decoded_data[SALT_LENGTH+16:SALT_LENGTH+32], 
            decoded_data[SALT_LENGTH+32:]
        )
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

### SECCIÓN 3: Asignación de nombres encriptados/desencriptados ###

def get_encrypted_filename(file_path: str) -> str:
    base, ext = os.path.splitext(file_path)
    return f"{base}_encrypted{ext}"

def get_decrypted_filename(file_path: str) -> str:
    if "_encrypted" in file_path:
        return file_path.replace("_encrypted", "_decrypted")
    base, ext = os.path.splitext(file_path)
    return f"{base}_decrypted{ext}"


### SECCIÓN 4: Encriptado/Desencriptado de clave privada de usuario ###

def encrypt_with_master_key(data: bytes, master_key: bytes) -> str:
    """
    Cifra los datos con la clave maestra utilizando AES en modo CBC.
    """
    cipher = AES.new(master_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return b64encode(cipher.iv + ciphertext).decode('utf-8')

def decrypt_with_master_key(encrypted_data: str, master_key: bytes) -> bytes:
    """
    Descifra los datos cifrados con la clave maestra utilizando AES en modo CBC.
    """
    encrypted_data = b64decode(encrypted_data)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

