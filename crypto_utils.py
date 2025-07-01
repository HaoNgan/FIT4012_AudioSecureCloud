# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import base64
import json
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class CryptoUtils:
    def __init__(self, session_key=None):
        self.rsa_key = RSA.generate(1024)
        self.public_key = self.rsa_key.publickey()
        self.session_key = session_key or get_random_bytes(32)
        logging.debug(f"Initialized session key: {self.session_key.hex()}")

    @staticmethod
    def hash_password(password):
        """Hash password using SHA512"""
        h = SHA512.new(password.encode())
        hashed = h.hexdigest()
        logging.debug(f"Hashed password: {hashed}")
        return hashed

    def sign_metadata(self, metadata):
        metadata_str = json.dumps(metadata, sort_keys=True)
        h = SHA512.new(metadata_str.encode())
        signature = pkcs1_15.new(self.rsa_key).sign(h)
        return signature  # Trả về bytes thay vì base64

    def verify_signature(self, metadata, signature, public_key):
        try:
            metadata_str = json.dumps(metadata, sort_keys=True)
            h = SHA512.new(metadata_str.encode())
            public_key = RSA.import_key(public_key)
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def compute_hash(self, nonce, ciphertext, tag):
        h = SHA512.new()
        h.update(nonce)
        h.update(ciphertext)
        h.update(tag)
        return h.digest()  # Trả về bytes thay vì base64

    def encrypt_session_key(self, public_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        enc_session_key = cipher.encrypt(self.session_key)
        logging.debug(f"Encrypted session key: {base64.b64encode(enc_session_key).decode()}")
        return enc_session_key  # Trả về bytes thay vì base64

    def encrypt_file(self, filepath):
        """Mã hóa file với streaming"""
        cipher = AES.new(self.session_key, AES.MODE_GCM)
        ciphertext = b""
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):  # Đọc từng chunk 64KB
                ct = cipher.encrypt(chunk)
                ciphertext += ct
        tag = cipher.digest()  # Tạo tag sau khi mã hóa toàn bộ
        logging.debug(f"Encryption - Nonce: {base64.b64encode(cipher.nonce).decode()}")
        logging.debug(f"Encryption - Tag: {base64.b64encode(tag).decode()}")
        return cipher.nonce, ciphertext, tag  # Trả về bytes thay vì base64

    def decrypt_file(self, nonce, ciphertext, tag, output_path):
        try:
            logging.debug(f"Decryption - Session key: {self.session_key.hex()}")
            logging.debug(f"Decryption - Nonce: {base64.b64encode(nonce).decode()}")
            logging.debug(f"Decryption - Tag: {base64.b64encode(tag).decode()}")
            cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            with open(output_path, "wb") as f:
                # Giải mã từng chunk nếu cần
                chunk_size = 65536
                for i in range(0, len(ciphertext), chunk_size):
                    chunk = ciphertext[i:i + chunk_size]
                    data = cipher.decrypt(chunk)
                    f.write(data)
            cipher.verify(tag)  # Xác minh tag
            logging.debug("Decryption successful")
            return True
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            return False