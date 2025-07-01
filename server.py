import base64
import socket
import json
import sqlite3
import os
import time
import logging
from datetime import datetime
from crypto_utils import CryptoUtils
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Server:
    def __init__(self):
        self.session_key = get_random_bytes(32)
        self.crypto = CryptoUtils(session_key=self.session_key)
        self.host = 'localhost'
        self.port = 12345
        self.buffer_size = 32768
        self.timeout = 30  # Tăng timeout
        self.init_db()
        logging.debug("Server initialized")

    def init_db(self):
        """Khởi tạo SQLite database"""
        conn = sqlite3.connect('cloud.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        filename TEXT PRIMARY KEY,
                        timestamp TEXT,
                        size INTEGER,
                        hash TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
                        timestamp TEXT,
                        event TEXT
                     )''')
        conn.commit()
        conn.close()
        logging.debug("Database initialized")

    def log_event(self, event, filename=None):
        """Ghi log vào SQLite"""
        event_str = event
        if filename:
            event_str += f" (File: {filename})"
        try:
            conn = sqlite3.connect('cloud.db')
            c = conn.cursor()
            c.execute('INSERT INTO logs VALUES (?, ?)',
                      (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), event_str))
            conn.commit()
            conn.close()
            logging.debug(f"Logged event: {event_str}")
        except Exception as e:
            logging.error(f"Log error: {str(e)}")

    def save_metadata(self, metadata, hash_value):
        """Lưu metadata vào SQLite"""
        try:
            conn = sqlite3.connect('cloud.db')
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO files (filename, timestamp, size, hash) VALUES (?, ?, ?, ?)',
                      (metadata['filename'],
                       datetime.fromtimestamp(metadata['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                       metadata['size'], base64.b64encode(hash_value).decode()))
            conn.commit()
            conn.close()
            logging.debug(f"Metadata saved for {metadata['filename']}")
            self.log_event("Metadata saved", metadata['filename'])
        except Exception as e:
            logging.error(f"Error saving metadata: {str(e)}")
            self.log_event(f"Error saving metadata: {str(e)}", metadata['filename'])

    def start(self):
        """Khởi động server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            server_socket.bind((self.host, self.port))
        except Exception as e:
            logging.error(f"Bind failed: {str(e)}")
            return
        server_socket.listen(5)
        server_socket.settimeout(self.timeout)
        logging.info(f"Server listening on {self.host}:{self.port}...")

        while True:
            try:
                conn, addr = server_socket.accept()
                conn.settimeout(10)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                logging.debug(f"Accepted connection from {addr}")
                # Nhận dữ liệu ban đầu
                data = b""
                chunk = conn.recv(self.buffer_size)
                if not chunk:
                    conn.close()
                    continue
                data += chunk
                try:
                    decoded_data = data.decode()
                    if decoded_data.startswith("Hello!"):
                        logging.debug("Received handshake: Hello!")
                        self.log_event("Handshake: Received Hello!")
                        conn.sendall("Ready!".encode())
                        conn.close()
                        continue
                    elif decoded_data.startswith("GET_PUBLIC_KEY"):
                        logging.debug("Received GET_PUBLIC_KEY request")
                        public_key = self.crypto.public_key.export_key().decode()
                        conn.sendall(f"PUBLIC_KEY:{public_key}".encode())
                        conn.close()
                        continue
                except UnicodeDecodeError:
                    pass
                # Nhận độ dài gói tin (4 bytes)
                length_data = data[:4] if len(data) >= 4 else b""
                while len(length_data) < 4:
                    chunk = conn.recv(4 - len(length_data))
                    if not chunk:
                        break
                    length_data += chunk
                if len(length_data) != 4:
                    logging.error("Failed to receive packet length")
                    response = {"status": "NACK: Failed to receive packet length", "time": 0}
                    response_data = json.dumps(response).encode()
                    conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                    conn.close()
                    continue
                length = int.from_bytes(length_data, 'big')
                logging.debug(f"Expected packet length: {length} bytes")
                data = data[4:] if len(data) > 4 else b""
                while len(data) < length:
                    chunk = conn.recv(min(self.buffer_size, length - len(data)))
                    if not chunk:
                        break
                    data += chunk
                if len(data) != length:
                    logging.error(f"Incomplete data received: {len(data)}/{length}")
                    response = {"status": "NACK: Incomplete data received", "time": 0}
                    response_data = json.dumps(response).encode()
                    conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                    conn.close()
                    continue
                try:
                    decoded_data = data.decode()
                    packet = json.loads(decoded_data)
                    logging.debug(f"Received packet for {packet['metadata'].get('filename', 'unknown') if isinstance(packet.get('metadata'), dict) else 'unknown'}")
                    # Deserialize metadata from JSON string
                    if isinstance(packet.get("metadata"), str):
                        try:
                            packet["metadata"] = json.loads(packet["metadata"])
                        except json.JSONDecodeError as e:
                            logging.error(f"Failed to decode metadata JSON: {str(e)}")
                            response = {"status": f"NACK: Invalid metadata: {str(e)}", "time": 0}
                            response_data = json.dumps(response).encode()
                            conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                            conn.close()
                            continue
                    cipher = PKCS1_OAEP.new(self.crypto.rsa_key)
                    self.crypto.session_key = cipher.decrypt(base64.b64decode(packet["session_key"]))
                    logging.debug(f"Decrypted session key: {self.crypto.session_key.hex()}")
                    if packet.get("request") == "download":
                        response = self.handle_download(packet)
                        self.log_event(f"Download: {response['status']}", packet["metadata"]["filename"])
                    else:
                        response = self.handle_upload(packet)
                        self.log_event(f"Upload: {response['status']}", packet["metadata"]["filename"])
                    response_data = json.dumps(response).encode()
                    conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                except json.JSONDecodeError as e:
                    logging.error(f"JSON decode error: {str(e)}")
                    self.log_event(f"JSON decode error: {str(e)}")
                    response = {"status": f"NACK: Invalid JSON: {str(e)}", "time": 0}
                    response_data = json.dumps(response).encode()
                    conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                except Exception as e:
                    logging.error(f"Processing error: {str(e)}")
                    self.log_event(f"Processing error: {str(e)}")
                    response = {"status": f"NACK: Processing error: {str(e)}", "time": 0}
                    response_data = json.dumps(response).encode()
                    conn.sendall(len(response_data).to_bytes(4, 'big') + response_data)
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Server error: {str(e)}")
                self.log_event(f"Server error: {str(e)}")

    def handle_upload(self, packet):
        """Xử lý upload"""
        try:
            start_time = time.time()
            logging.debug(f"Handling upload for {packet['metadata']['filename']}")

            if not self.crypto.verify_signature(packet["metadata"], base64.b64decode(packet["sig"]), packet["public_key"]):
                logging.error("Invalid signature")
                return {"status": "NACK: Invalid signature", "time": 0}

            computed_hash = self.crypto.compute_hash(
                base64.b64decode(packet["nonce"]),
                base64.b64decode(packet["cipher"]),
                base64.b64decode(packet["tag"])
            )
            if computed_hash != base64.b64decode(packet["hash"]):
                logging.error("Hash mismatch")
                return {"status": "NACK: Hash mismatch", "time": 0}

            output_path = f"uploads/{packet['metadata']['filename']}"
            logging.debug(f"Saving file to: {output_path}")
            if self.crypto.decrypt_file(
                base64.b64decode(packet["nonce"]),
                base64.b64decode(packet["cipher"]),
                base64.b64decode(packet["tag"]),
                output_path
            ):
                logging.debug("Decrypt successful, saving metadata")
                self.save_metadata(packet["metadata"], computed_hash)
                end_time = time.time()
                return {"status": "ACK: File saved", "time": end_time - start_time}
            else:
                logging.error("Tag mismatch")
                return {"status": "NACK: Tag mismatch", "time": 0}
        except Exception as e:
            logging.error(f"Upload error: {str(e)}")
            return {"status": f"Error: {str(e)}", "time": 0}

    def handle_download(self, packet):
        try:
            start_time = time.time()
            filename = packet["metadata"]["filename"]
            filepath = f"uploads/{filename}"
            logging.debug(f"Handling download for {filename}")

            if not os.path.exists(filepath):
                logging.error("File not found")
                return {"status": "NACK: File not found", "time": 0}

            if not self.crypto.verify_signature(packet["metadata"], base64.b64decode(packet["sig"]), packet["public_key"]):
                logging.error("Invalid signature")
                return {"status": "NACK: Invalid signature", "time": 0}

            encrypt_start = time.time()
            nonce, ciphertext, tag = self.crypto.encrypt_file(filepath)
            encrypt_time = time.time() - encrypt_start
            hash_value = self.crypto.compute_hash(nonce, ciphertext, tag)

            end_time = time.time()
            logging.debug("Download prepared successfully")
            # Ký metadata bằng private key của server
            signature = self.crypto.sign_metadata(packet["metadata"])  # Sử dụng sign_metadata thay vì sign_data
            return {
                "status": "ACK",
                "metadata": packet["metadata"],
                "nonce": base64.b64encode(nonce).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
                "hash": base64.b64encode(hash_value).decode(),
                "time": end_time - start_time,
                "encrypt_time": encrypt_time,
                "sig": base64.b64encode(signature).decode()  # Thêm chữ ký
            }
        except Exception as e:
            logging.error(f"Download error: {str(e)}")
            return {"status": f"Error: {str(e)}", "time": 0, "encrypt_time": 0}

if __name__ == '__main__':
    server = Server()
    server.start()