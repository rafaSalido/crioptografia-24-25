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
COMM_FOLDER = os.path.join(CERTIFICATES_FOLDER, "communities")

# Crear carpetas necesarias
os.makedirs(CERTIFICATES_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(USERS_FOLDER, exist_ok=True)
os.makedirs(COMM_FOLDER, exist_ok=True)

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
    try:
        with open(ENCRYPTED_PRIVATE_KEY_PATH, 'wb') as key_file:
            key_file.write(encrypted_private_key)
        logger.info("Clave privada de la aplicación cifrada y guardada con éxito.")
    except IOError as e:
        logger.error(f"Error al guardar la clave privada cifrada: {e}")
        raise

    # Guardar la clave pública
    try:
        with open(APP_PUBLIC_KEY_PATH, "w") as pub_key_file:
            pub_key_file.write(APP_PUBLIC_KEY.hex())
        logger.info("Clave pública de la aplicación guardada con éxito.")
    except IOError as e:
        logger.error(f"Error al guardar la clave pública: {e}")
        raise
else:
    # Cargar la clave pública
    try:
        with open(APP_PUBLIC_KEY_PATH, "r") as pub_key_file:
            APP_PUBLIC_KEY = bytes.fromhex(pub_key_file.read())
        logger.info("Clave pública de la aplicación cargada correctamente.")
    except IOError as e:
        logger.error(f"Error al cargar la clave pública: {e}")
        raise

    # Cargar y descifrar la clave privada de la aplicación
    try:
        with open(ENCRYPTED_PRIVATE_KEY_PATH, "rb") as key_file:
            encrypted_private_key = key_file.read()

        # Derivar la clave de cifrado desde LICENSE_KEY
        derived_key = derive_key_from_license(LICENSE_KEY)

        # Extraer IV y descifrar la clave privada
        iv = encrypted_private_key[:16]
        ciphertext = encrypted_private_key[16:]
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        APP_PRIVATE_KEY = unpad(cipher.decrypt(ciphertext), AES.block_size)
        logger.info("Clave privada de la aplicación descifrada correctamente.")
    except Exception as e:
        logger.error(f"Error al descifrar la clave privada: {e}")
        raise

# Funciones para certificados de usuarios
def generate_certificate(identifier: str, kyber_public_key: bytes, is_community=False) -> str:
    """
    Genera un certificado básico para un usuario o comunidad, lo firma y lo guarda en disco.
    """
    kyber_public_key = bytes.fromhex(kyber_public_key) if isinstance(kyber_public_key, str) else kyber_public_key

    # Crear el contenido del certificado
    certificate = {
        "identifier": identifier,
        "kyber_public_key": kyber_public_key.hex()
    }

    # Firmar el certificado con la clave privada de la aplicación
    certificate_data = json.dumps(certificate).encode()
    try:
        certificate["signature"] = Dilithium2.sign(APP_PRIVATE_KEY, certificate_data).hex()
        logger.info(f"Certificado firmado para {identifier}.")
    except Exception as e:
        logger.error(f"Error al firmar el certificado: {e}")
        raise RuntimeError(f"Error al firmar el certificado: {e}")

    # Guardar el certificado en la carpeta correspondiente
    folder = COMM_FOLDER if is_community else USERS_FOLDER
    extension = "json"
    certificate_path = os.path.join(folder, f"{identifier}_certificate.{extension}")

    try:
        with open(certificate_path, 'w') as cert_file:
            json.dump(certificate, cert_file, indent=4)
        logger.info(f"Certificado generado y guardado para: {identifier}")
    except Exception as e:
        logger.error(f"Error al guardar el certificado: {e}")
        raise IOError(f"Error al guardar el certificado: {e}")

    return certificate_path

def validate_certificate(identifier: str, is_community: bool = False) -> bool:
    """
    Valida un certificado contra la clave pública de la aplicación.
    
    :param identifier: Nombre del usuario o comunidad.
    :param is_community: Booleano que indica si el certificado es para una comunidad.
    :return: True si el certificado es válido, False en caso contrario.
    """
    folder = COMM_FOLDER if is_community else USERS_FOLDER
    extension = "json"
    certificate_path = os.path.join(folder, f"{identifier}_certificate.{extension}")

    if not os.path.exists(certificate_path):
        logger.error(f"Certificado para {identifier} no encontrado.")
        return False

    # Cargar el certificado
    try:
        with open(certificate_path, 'r') as cert_file:
            certificate = json.load(cert_file)
        logger.info(f"Certificado cargado correctamente para {identifier}.")
    except IOError as e:
        logger.error(f"Error al cargar el certificado para {identifier}: {e}")
        return False

    # Extraer y verificar la firma
    try:
        cert_copy = certificate.copy()
        signature = bytes.fromhex(cert_copy.pop("signature"))
        certificate_data = json.dumps(cert_copy).encode()

        # Verificar la firma con la clave pública de la aplicación
        is_valid = Dilithium2.verify(APP_PUBLIC_KEY, certificate_data, signature)
        if is_valid:
            logger.info(f"El certificado para {identifier} es válido.")
        else:
            logger.warning(f"El certificado para {identifier} no es válido.")
        return is_valid
    except Exception as e:
        logger.error(f"Error al validar el certificado: {e}")
        return False