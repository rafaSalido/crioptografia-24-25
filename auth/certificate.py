import os
import json
from dotenv import load_dotenv
from dilithium.dilithium import Dilithium2
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging

# Cargar variables de entorno
load_dotenv()

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Carpetas de Certificados
CERTIFICATES_FOLDER = "certificates"
KEYS_FOLDER = os.path.join(CERTIFICATES_FOLDER, "keys")
USERS_FOLDER = os.path.join(CERTIFICATES_FOLDER, "users")

# Crear carpetas necesarias
os.makedirs(CERTIFICATES_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(USERS_FOLDER, exist_ok=True)

# Cargar número de licencia para proteger la clave privada de la aplicación
LICENSE_KEY = os.getenv("LICENSE_KEY").encode("utf-8")

# Parámetros para derivación de clave
SALT_LENGTH = 16
KEY_LENGTH = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

# Rutas de las claves de la aplicación
APP_PUBLIC_KEY_PATH = os.path.join(KEYS_FOLDER, "app_public_key.pem")
ENCRYPTED_PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "encrypted_app_private_key.pem")

def derive_key_from_license(license_key: bytes) -> bytes:
    """
    Deriva una clave AES a partir del número de licencia utilizando scrypt.
    """
    salt = b'some_fixed_salt'  # Utiliza un valor fijo para derivar siempre la misma clave.
    return scrypt(license_key, salt, KEY_LENGTH, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)

# Generar claves de la aplicación si no existen
if not os.path.exists(ENCRYPTED_PRIVATE_KEY_PATH) or not os.path.exists(APP_PUBLIC_KEY_PATH):
    logger.info("Generando claves de la aplicación...")
    APP_PUBLIC_KEY, APP_PRIVATE_KEY = Dilithium2.keygen()

    # Asegurarse de que APP_PRIVATE_KEY es bytes
    if isinstance(APP_PRIVATE_KEY, str):
        APP_PRIVATE_KEY = APP_PRIVATE_KEY.encode('utf-8')

    # Derivar la clave de cifrado desde LICENSE_KEY
    derived_key = derive_key_from_license(LICENSE_KEY)

    # Cifrar la clave privada de la aplicación usando AES en modo CBC
    iv = os.urandom(16)  # Vector de inicialización (IV) aleatorio
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    padded_private_key = pad(APP_PRIVATE_KEY, AES.block_size)
    encrypted_private_key = iv + cipher.encrypt(padded_private_key)

    # Guardar la clave privada cifrada
    with open(ENCRYPTED_PRIVATE_KEY_PATH, 'wb') as key_file:
        key_file.write(encrypted_private_key)

    # Guardar la clave pública
    with open(APP_PUBLIC_KEY_PATH, "w") as pub_key_file:
        pub_key_file.write(APP_PUBLIC_KEY.hex())
else:
    # Cargar la clave pública
    with open(APP_PUBLIC_KEY_PATH, "r") as pub_key_file:
        APP_PUBLIC_KEY = bytes.fromhex(pub_key_file.read())

    # Cargar y descifrar la clave privada de la aplicación
    with open(ENCRYPTED_PRIVATE_KEY_PATH, "rb") as key_file:
        encrypted_private_key = key_file.read()

    # Derivar la clave de cifrado desde LICENSE_KEY
    derived_key = derive_key_from_license(LICENSE_KEY)

    # Extraer IV y descifrar la clave privada
    iv = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    APP_PRIVATE_KEY = unpad(cipher.decrypt(ciphertext), AES.block_size)

# Funciones para certificados de usuarios
def generate_certificate(username: str, kyber_public_key: bytes) -> str:
    """
    Genera un certificado básico para un usuario, lo firma y lo guarda en disco.
    """
    kyber_public_key = bytes.fromhex(kyber_public_key) if isinstance(kyber_public_key, str) else kyber_public_key

    # Crear el contenido del certificado
    user_certificate = {
        "username": username,
        "kyber_public_key": kyber_public_key.hex()
    }

    # Firmar el certificado con la clave privada de la aplicación
    certificate_data = json.dumps(user_certificate).encode()
    try:
        user_certificate["signature"] = Dilithium2.sign(APP_PRIVATE_KEY, certificate_data).hex()
    except Exception as e:
        logger.error(f"Error al firmar el certificado: {e}")
        raise RuntimeError(f"Error al firmar el certificado: {e}")

    # Guardar el certificado en la carpeta de usuarios
    certificate_path = os.path.join(USERS_FOLDER, f"{username}_certificate.json")
    try:
        with open(certificate_path, 'w') as cert_file:
            json.dump(user_certificate, cert_file, indent=4)
        logger.info(f"Certificado generado para el usuario: {username}")
    except Exception as e:
        logger.error(f"Error al guardar el certificado: {e}")
        raise IOError(f"Error al guardar el certificado: {e}")

    return certificate_path

def validate_certificate(username: str) -> bool:
    """
    Valida un certificado de usuario contra la clave pública de la aplicación.
    """
    certificate_path = os.path.join(USERS_FOLDER, f"{username}_certificate.json")
    if not os.path.exists(certificate_path):
        raise FileNotFoundError(f"Certificado para {username} no encontrado.")

    # Cargar el certificado
    with open(certificate_path, 'r') as cert_file:
        certificate = json.load(cert_file)

    # Extraer y verificar la firma
    try:
        cert_copy = certificate.copy()
        signature = bytes.fromhex(cert_copy.pop("signature"))
        certificate_data = json.dumps(cert_copy).encode()

        # Verificar la firma con la clave pública de la aplicación
        is_valid = Dilithium2.verify(APP_PUBLIC_KEY, certificate_data, signature)
        if is_valid:
            logger.info(f"El certificado del usuario {username} es válido.")
        else:
            logger.warning(f"El certificado del usuario {username} no es válido.")
        return is_valid
    except Exception as e:
        logger.error(f"Error al validar el certificado: {e}")
        raise ValueError(f"Error al validar el certificado: {e}")
