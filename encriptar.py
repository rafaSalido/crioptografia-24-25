import os
import logging
from typing import Optional, Tuple, Union
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Padding

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants
MIN_PASSWORD_LENGTH = 5
SALT_LENGTH = 16
IV_LENGTH = 16
KEY_LENGTH = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

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
        """
        Encrypt data using AES-CBC mode with PKCS7 padding.
        
        Args:
            data: Bytes to encrypt
            
        Returns:
            Tuple of (iv, ciphertext)
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            iv = get_random_bytes(IV_LENGTH)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = Padding.pad(data, AES.block_size)
            return iv, cipher.encrypt(padded_data)
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise EncryptionError("Failed to encrypt data")

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt data using AES-CBC mode with PKCS7 padding.
        
        Args:
            iv: Initialization vector
            ciphertext: Encrypted data
            
        Returns:
            Decrypted data
            
        Raises:
            EncryptionError: If decryption fails
        """
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)
            return Padding.unpad(decrypted_data, AES.block_size)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise EncryptionError("Failed to decrypt data")

def is_strong_password(password: str) -> bool:
    """
    Verify password meets minimum requirements.
    
    Args:
        password: Password to verify
        
    Returns:
        True if password meets requirements, False otherwise
    """
    if not isinstance(password, str):
        return False
    return len(password) >= MIN_PASSWORD_LENGTH

def get_encrypted_filename(file_path: str) -> str:
    """
    Generate encrypted filename.
    
    Args:
        file_path: Original file path
        
    Returns:
        Path with '_encrypted' suffix
    """
    base, ext = os.path.splitext(file_path)
    return f"{base}_encrypted{ext}"

def get_decrypted_filename(file_path: str) -> str:
    """
    Generate decrypted filename.
    
    Args:
        file_path: Encrypted file path
        
    Returns:
        Path with '_decrypted' suffix
    """
    if "_encrypted" in file_path:
        return file_path.replace("_encrypted", "_decrypted")
    base, ext = os.path.splitext(file_path)
    return f"{base}_decrypted{ext}"

def encrypt_file(file_path: str, password: str) -> Optional[str]:
    """
    Encrypt a file using AES-CBC.
    
    Args:
        file_path: Path to file to encrypt
        password: Encryption password
        
    Returns:
        Path to encrypted file or None if encryption fails
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        if not is_strong_password(password):
            logger.error(f"Password too weak (minimum {MIN_PASSWORD_LENGTH} characters required)")
            return None

        # Read file in binary mode
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Generate salt and create cipher
        salt = get_random_bytes(SALT_LENGTH)
        cipher = AESCipher(password, salt)
        
        # Encrypt data
        iv, ciphertext = cipher.encrypt(file_data)
        
        # Generate output filename and write encrypted data
        encrypted_file_path = get_encrypted_filename(file_path)
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + iv + ciphertext)

        logger.debug(f"File encrypted successfully: {encrypted_file_path}")
        return encrypted_file_path

    except EncryptionError as e:
        logger.error(f"Encryption error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during encryption: {str(e)}")
        return None

def decrypt_file(encrypted_file_path: str, password: str) -> Optional[str]:
    """
    Decrypt a file using AES-CBC.
    
    Args:
        encrypted_file_path: Path to encrypted file
        password: Decryption password
        
    Returns:
        Path to decrypted file or None if decryption fails
    """
    try:
        if not os.path.exists(encrypted_file_path):
            logger.error(f"File not found: {encrypted_file_path}")
            return None

        if not is_strong_password(password):
            logger.error(f"Password too weak (minimum {MIN_PASSWORD_LENGTH} characters required)")
            return None

        # Read encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Extract salt, IV, and ciphertext
        if len(encrypted_data) < SALT_LENGTH + IV_LENGTH:
            logger.error("Encrypted file is too short")
            return None

        salt = encrypted_data[:SALT_LENGTH]
        iv = encrypted_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
        ciphertext = encrypted_data[SALT_LENGTH + IV_LENGTH:]

        # Create cipher and decrypt
        cipher = AESCipher(password, salt)
        decrypted_data = cipher.decrypt(iv, ciphertext)

        # Write decrypted data
        decrypted_file_path = get_decrypted_filename(encrypted_file_path)
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        logger.debug(f"File decrypted successfully: {decrypted_file_path}")
        return decrypted_file_path

    except EncryptionError as e:
        logger.error(f"Decryption error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during decryption: {str(e)}")
        return None

def handle_compressed_or_file(file_path: str, password: str, action: str) -> Optional[str]:
    """
    Handle encryption/decryption of files.
    
    Args:
        file_path: Path to file
        password: Password for encryption/decryption
        action: 'encrypt' or 'decrypt'
        
    Returns:
        Path to output file or None if operation fails
    """
    try:
        if action == 'encrypt':
            logger.info(f"Encrypting file: {file_path}")
            return encrypt_file(file_path, password)
        elif action == 'decrypt':
            logger.info(f"Decrypting file: {file_path}")
            return decrypt_file(file_path, password)
        else:
            logger.error(f"Invalid action: {action}")
            return None
    except Exception as e:
        logger.error(f"Error handling file: {str(e)}")
        return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files.")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('file_path', help="Path to file")
    parser.add_argument('password', help="Password for encryption/decryption")
    
    args = parser.parse_args()
    
    result = handle_compressed_or_file(args.file_path, args.password, args.action)
    if result:
        print(f"Operation successful. Output file: {result}")
    else:
        print("Operation failed. Check logs for details.")