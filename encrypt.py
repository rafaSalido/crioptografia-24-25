import os
import logging
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from dotenv import load_dotenv
from kyber.kyber import Kyber512 

# Cargar variables de entorno y configurar logging
load_dotenv()
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Clave maestra desde .env para encriptación de datos sensibles
MASTER_KEY = os.getenv('ENCRYPTION_KEY').encode('utf-8')

# Constantes
MIN_PASSWORD_LENGTH = 5  # Longitud mínima de contraseña permitida
SALT_LENGTH = 16  # Longitud del salt para derivación de claves
IV_LENGTH = 16  # Longitud del vector de inicialización (IV)
KEY_LENGTH = 32  # Longitud de la clave generada
SCRYPT_N = 2**14  # Parámetro N para el algoritmo Scrypt (factor de costo)
SCRYPT_R = 8  # Parámetro R para el algoritmo Scrypt
SCRYPT_P = 1  # Parámetro P para el algoritmo Scrypt

### Encriptación y Desencriptación de Claves AES usando Kyber512 ###

def encrypt_aes_key_with_kyber(aes_key: bytes, public_key_hex: str) -> str:
    """
    Cifra la clave AES utilizando la clave pública de Kyber512.
    """
    kyber = Kyber512
    public_key = bytes.fromhex(public_key_hex)
    shared_key, ciphertext = kyber.encaps(public_key)  # Encapsulación para generar ciphertext
    logger.debug(f"Clave AES cifrada correctamente con la clave pública Kyber512. Shared key: {shared_key.hex()}")
    return b64encode(ciphertext).decode('utf-8')  # Retornar el ciphertext en base64

def decrypt_aes_key_with_kyber(ciphertext_b64: str, private_key_hex: str) -> bytes:
    """
    Decapsula el ciphertext para recuperar la clave AES utilizando la clave privada Kyber512.
    """
    kyber = Kyber512
    private_key = bytes.fromhex(private_key_hex)
    ciphertext = b64decode(ciphertext_b64)

    # Recuperar la clave compartida
    try:
        shared_key = kyber.decaps(private_key, ciphertext)
        logger.debug("Clave AES descifrada correctamente con la clave privada Kyber512.")
        return shared_key  # Retornar la clave compartida recuperada
    except Exception as e:
        logger.error(f"Error durante la decapsulación con Kyber512: {str(e)}")
        raise EncryptionError("Failed to decrypt the AES key using Kyber512")

### SECCIÓN 1: Encriptación de Archivos del Usuario ###

class EncryptionError(Exception):
    pass

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key  # Inicializa el cifrador AES con la clave proporcionada

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Cifra los datos proporcionados utilizando AES en modo CBC.
        """
        iv = get_random_bytes(IV_LENGTH)  # Generar un IV aleatorio
        cipher = AES.new(self.key, AES.MODE_CBC, iv)  # Inicializar cifrador AES con la clave y el IV
        padded_data = pad(data, AES.block_size)  # Rellenar los datos para que sean múltiplos del tamaño de bloque
        return iv, cipher.encrypt(padded_data)  # Retornar IV y el ciphertext cifrado

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Descifra los datos cifrados utilizando AES en modo CBC.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, iv)  # Inicializar cifrador AES con la clave y el IV
        decrypted_data = cipher.decrypt(ciphertext)  # Descifrar los datos
        return unpad(decrypted_data, AES.block_size)  # Retornar los datos descifrados después de eliminar el padding

def encrypt_file(file_path: str, aes_key: bytes) -> Optional[str]:
    """
    Cifra un archivo en la ruta especificada utilizando la clave AES proporcionada.
    """
    if not os.path.exists(file_path):
        logger.error("File not found")
        return None  # Error si el archivo no existe

    with open(file_path, 'rb') as file:
        file_data = file.read()  # Leer el contenido del archivo

    cipher = AESCipher(aes_key)  # Inicializar cifrador AES con la clave proporcionada
    iv, ciphertext = cipher.encrypt(file_data)  # Cifrar los datos del archivo
    
    encrypted_file_path = get_encrypted_filename(file_path)  # Obtener el nombre para el archivo cifrado
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)  # Escribir el IV y el ciphertext en el archivo cifrado

    logger.debug(f"File encrypted successfully: {encrypted_file_path}")
    return encrypted_file_path  # Retornar la ruta del archivo cifrado

def decrypt_file(encrypted_file_path: str, aes_key: bytes) -> Optional[str]:
    """
    Descifra un archivo cifrado en la ruta especificada utilizando la clave AES proporcionada.
    """
    if not os.path.exists(encrypted_file_path):
        logger.error("File not found")
        return None  # Error si el archivo no existe

    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()  # Leer el contenido cifrado del archivo

    iv = encrypted_data[:IV_LENGTH]  # Extraer el IV del inicio del archivo
    ciphertext = encrypted_data[IV_LENGTH:]  # Extraer el ciphertext del resto del archivo

    cipher = AESCipher(aes_key)  # Inicializar cifrador AES
    decrypted_data = cipher.decrypt(iv, ciphertext)  # Descifrar los datos

    decrypted_file_path = get_decrypted_filename(encrypted_file_path)  # Obtener el nombre para el archivo descifrado
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)  # Escribir los datos descifrados en el archivo

    logger.debug(f"File decrypted successfully: {decrypted_file_path}")
    return decrypted_file_path  # Retornar la ruta del archivo descifrado

### SECCIÓN 2: Encriptación de Datos Sensibles del Backend ###

class MasterCipher:
    def __init__(self, key: bytes = MASTER_KEY):
        self.key = key  # Inicializar cifrador maestro con la clave proporcionada

    def encrypt(self, data: str) -> str:
        """
        Cifra los datos sensibles proporcionados utilizando la clave maestra en modo EAX.
        """
        salt = get_random_bytes(SALT_LENGTH)  # Generar un salt aleatorio
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=8, p=1)  # Derivar la clave con Scrypt
        cipher = AES.new(key, AES.MODE_EAX)  # Inicializar cifrador AES en modo EAX
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())  # Cifrar los datos y generar un tag
        return b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')  # Retornar todos los componentes cifrados en base64

    def decrypt(self, encrypted_data: str) -> str:
        """
        Descifra los datos sensibles cifrados utilizando la clave maestra en modo EAX.
        """
        decoded_data = b64decode(encrypted_data)  # Decodificar los datos cifrados en base64
        salt, nonce, tag, ciphertext = (
            decoded_data[:SALT_LENGTH], 
            decoded_data[SALT_LENGTH:SALT_LENGTH+16], 
            decoded_data[SALT_LENGTH+16:SALT_LENGTH+32], 
            decoded_data[SALT_LENGTH+32:]
        )  # Extraer el salt, nonce, tag y el ciphertext
        key = scrypt(self.key, salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)  # Derivar la clave con Scrypt
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Inicializar cifrador AES en modo EAX
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')  # Descifrar y verificar los datos, luego retornarlos como string

### SECCIÓN 3: Asignación de nombres encriptados/desencriptados ###

def get_encrypted_filename(file_path: str) -> str:
    """
    Genera el nombre del archivo cifrado a partir del nombre original.
    """
    base, ext = os.path.splitext(file_path)
    return f"{base}_encrypted{ext}"

def get_decrypted_filename(file_path: str) -> str:
    """
    Genera el nombre del archivo descifrado a partir del nombre cifrado.
    """
    if "_encrypted" in file_path:
        return file_path.replace("_encrypted", "_decrypted")
    base, ext = os.path.splitext(file_path)
    return f"{base}_decrypted{ext}"

### SECCIÓN 4: Encriptado/Desencriptado de clave privada de usuario ###

def encrypt_with_master_key(data: bytes, master_key: bytes) -> str:
    """
    Cifra los datos con la clave maestra utilizando AES en modo CBC.
    """
    iv = os.urandom(IV_LENGTH)  # Genera un IV aleatorio.
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return b64encode(iv + ciphertext).decode('utf-8')

def decrypt_with_master_key(encrypted_data: str, master_key: bytes) -> bytes:
    """
    Descifra los datos cifrados con la clave maestra utilizando AES en modo CBC.
    """
    encrypted_data = b64decode(encrypted_data)
    iv, ciphertext = encrypted_data[:IV_LENGTH], encrypted_data[IV_LENGTH:]
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)