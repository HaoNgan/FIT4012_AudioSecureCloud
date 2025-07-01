# client.py
import socket
import json
import os
import time
import base64
import logging
from crypto_utils import CryptoUtils

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('client.log'), logging.StreamHandler()]
)

class Client:
    def __init__(self, filepath=None, host='localhost', port=12345):
        self.filepath = filepath
        self.host = host
        self.port = port
        self.buffer_size = 65536
        self.crypto = CryptoUtils()
        self.server_public_key = self.get_server_public_key()
        self.uploaded_files = {}  # Lưu thông tin file đã upload để dùng cho download
        logging.debug("Client initialized")

    def get_server_public_key(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((self.host, self.port))
            client_socket.sendall("GET_PUBLIC_KEY".encode())
            response = client_socket.recv(4096).decode()
            client_socket.close()
            if response.startswith("PUBLIC_KEY:"):
                public_key = response[len("PUBLIC_KEY:"):]
                logging.debug(f"Received server public key: {public_key}")
                return public_key
            raise Exception("Invalid public key response")
        except Exception as e:
            logging.error(f"Failed to get server public key: {str(e)}")
            raise

    def handshake(self, retries=3, delay=1):
        logging.debug(f"Starting handshake with {retries} retries")
        for attempt in range(retries):
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(10)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                logging.debug(f"Attempt {attempt + 1}: Connecting to {self.host}:{self.port}")
                client_socket.connect((self.host, self.port))
                logging.debug("Sending Hello!")
                client_socket.sendall("Hello!".encode())
                response = client_socket.recv(1024).decode()
                logging.debug(f"Received response: {response}")
                client_socket.close()
                return response == "Ready!", response
            except Exception as e:
                logging.error(f"Handshake attempt {attempt + 1} failed: {str(e)}")
                if attempt < retries - 1:
                    time.sleep(delay)
                    continue
                return False, str(e)
        logging.error("Handshake failed after all retries")
        return False, "Handshake failed after retries"

    def upload(self, simulate_attack=False, retries=3, delay=1):
        for attempt in range(retries):
            try:
                start_time = time.time()
                logging.debug(f"Upload attempt {attempt + 1} for file: {self.filepath}")
                metadata = {
                    "filename": os.path.basename(self.filepath),
                    "timestamp": int(time.time()),
                    "size": os.path.getsize(self.filepath)
                }
                signature = self.crypto.sign_metadata(metadata)
                encrypt_start = time.time()
                nonce, ciphertext, tag = self.crypto.encrypt_file(self.filepath)
                encrypt_time = time.time() - encrypt_start
                if simulate_attack:
                    tampered = bytearray(ciphertext)
                    tampered[-1] = (tampered[-1] + 1) % 256
                    ciphertext = bytes(tampered)
                hash_value = self.crypto.compute_hash(nonce, ciphertext, tag)
                enc_session_key = self.crypto.encrypt_session_key(self.server_public_key)
                packet = {
                    "nonce": base64.b64encode(nonce).decode(),
                    "cipher": base64.b64encode(ciphertext).decode(),
                    "tag": base64.b64encode(tag).decode(),
                    "hash": base64.b64encode(hash_value).decode(),
                    "sig": base64.b64encode(signature).decode(),
                    "session_key": base64.b64encode(enc_session_key).decode(),
                    "metadata": metadata,
                    "public_key": self.crypto.public_key.export_key().decode()
                }
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(30)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                logging.debug("Connecting to server for upload")
                client_socket.connect((self.host, self.port))
                packet_data = json.dumps(packet).encode('utf-8')
                length = len(packet_data)
                client_socket.sendall(length.to_bytes(4, 'big'))
                logging.debug(f"Sent packet length: {length}")
                total_sent = 0
                while total_sent < len(packet_data):
                    sent = client_socket.send(packet_data[total_sent:])
                    if sent == 0:
                        raise RuntimeError("Socket connection broken")
                    total_sent += sent
                logging.debug(f"Sent {total_sent} bytes")
                length_data = b""
                while len(length_data) < 4:
                    chunk = client_socket.recv(4 - len(length_data))
                    if not chunk:
                        break
                    length_data += chunk
                if len(length_data) != 4:
                    raise RuntimeError("Failed to receive response length")
                length = int.from_bytes(length_data, 'big')
                response_data = b""
                while len(response_data) < length:
                    chunk = client_socket.recv(min(self.buffer_size, length - len(response_data)))
                    if not chunk:
                        break
                    response_data += chunk
                response = json.loads(response_data.decode())
                client_socket.close()
                logging.debug(f"Upload response: {response}")
                if response["status"].startswith("ACK"):
                    self.uploaded_files[metadata["filename"]] = {
                        "session_key": self.crypto.session_key,
                        "metadata": metadata,
                        "signature": signature
                    }
                    logging.debug(f"Uploaded files updated: {self.uploaded_files}")
                    end_time = time.time()
                    return {
                        "status": response["status"],
                        "time": end_time - start_time,
                        "encrypt_time": encrypt_time
                    }
                else:
                    logging.error(f"Upload failed with status: {response['status']}")
                    return {"status": response["status"], "time": 0, "encrypt_time": 0}
            except Exception as e:
                logging.error(f"Upload attempt {attempt + 1} failed: {str(e)}")
                if attempt < retries - 1:
                    time.sleep(delay)
                    continue
                return {"status": f"Error: {str(e)}", "time": 0, "encrypt_time": 0}

    def download(self, filename, retries=3, delay=1):
        for attempt in range(retries):
            try:
                start_time = time.time()
                logging.debug(f"Download attempt {attempt + 1} for file: {filename}")
                if filename not in self.uploaded_files:
                    logging.error(f"No upload info found for {filename}. Uploaded files: {self.uploaded_files}")
                    return {"status": "NACK: No upload info", "time": 0}
                file_info = self.uploaded_files[filename]
                session_key = file_info["session_key"]
                metadata = file_info["metadata"]
                signature = file_info["signature"]
                self.crypto = CryptoUtils(session_key=session_key)
                enc_session_key = self.crypto.encrypt_session_key(self.server_public_key)
                packet = {
                    "request": "download",
                    "metadata": metadata,
                    "sig": base64.b64encode(signature).decode(),
                    "session_key": base64.b64encode(enc_session_key).decode(),
                    "public_key": self.crypto.public_key.export_key().decode()
                }
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(30)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                logging.debug("Connecting to server for download")
                client_socket.connect((self.host, self.port))
                packet_data = json.dumps(packet).encode('utf-8')
                length = len(packet_data)
                client_socket.sendall(length.to_bytes(4, 'big'))
                logging.debug(f"Sent packet length: {length}")
                total_sent = 0
                while total_sent < len(packet_data):
                    sent = client_socket.send(packet_data[total_sent:])
                    if sent == 0:
                        raise RuntimeError("Socket connection broken")
                    total_sent += sent
                logging.debug(f"Sent {total_sent} bytes")
                length_data = b""
                while len(length_data) < 4:
                    chunk = client_socket.recv(4 - len(length_data))
                    if not chunk:
                        break
                    length_data += chunk
                if len(length_data) != 4:
                    raise RuntimeError("Failed to receive response length")
                length = int.from_bytes(length_data, 'big')
                response_data = b""
                while len(response_data) < length:
                    chunk = client_socket.recv(min(self.buffer_size, length - len(response_data)))
                    if not chunk:
                        break
                    response_data += chunk
                response = json.loads(response_data.decode())
                client_socket.close()
                logging.debug(f"Download response: {response}")
                if response["status"] == "ACK":
                    if not self.crypto.verify_signature(response["metadata"], base64.b64decode(response["sig"]), self.server_public_key):
                        return {"status": "NACK: Invalid signature from server", "time": 0}
                    computed_hash = self.crypto.compute_hash(
                        base64.b64decode(response["nonce"]),
                        base64.b64decode(response["cipher"]),
                        base64.b64decode(response["tag"])
                    )
                    if computed_hash != base64.b64decode(response["hash"]):
                        return {"status": "NACK: Hash mismatch", "time": 0}
                    decrypt_start = time.time()
                    output_path = f"uploads/downloaded_{filename}"
                    if self.crypto.decrypt_file(
                        base64.b64decode(response["nonce"]),
                        base64.b64decode(response["cipher"]),
                        base64.b64decode(response["tag"]),
                        output_path
                    ):
                        decrypt_time = time.time() - decrypt_start
                        end_time = time.time()
                        return {
                            "status": "Download successful",
                            "time": end_time - start_time,
                            "decrypt_time": decrypt_time
                        }
                    else:
                        return {"status": "NACK: Tag mismatch", "time": 0}
                else:
                    return {"status": response["status"], "time": 0}
            except Exception as e:
                logging.error(f"Download attempt {attempt + 1} failed: {str(e)}")
                if attempt < retries - 1:
                    time.sleep(delay)
                    continue
                return {"status": f"Error: {str(e)}", "time": 0, "decrypt_time": 0}

if __name__ == '__main__':
    client = Client("ThienLyOi-JackJ97-13829746.mp3")
    if client.handshake()[0]:
        result = client.upload()
        print(f"Upload result: {result}")
        result = client.download("ThienLyOi-JackJ97-13829746.mp3")
        print(f"Download result: {result}")