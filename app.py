import base64
import socket
import time
from flask import Flask, request, render_template, session, redirect, url_for, send_file
import os
import sqlite3
import logging
import json
from client import Client
from crypto_utils import CryptoUtils
from Crypto.PublicKey import RSA

app = Flask(__name__)
app.secret_key = 'secure_file_transfer_secret'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp3'}

# Cấu hình logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

users = {
    'admin': CryptoUtils.hash_password('admin123'),
    'user': CryptoUtils.hash_password('user123')
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = CryptoUtils.hash_password(request.form['password'])
        if username in users and users[username] == password:
            session['username'] = username
            session['uploaded_files'] = session.get('uploaded_files', {})  # Khởi tạo nếu chưa có
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('uploaded_files', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        client = Client(None)
        handshake_success, handshake_response = client.handshake()
        handshake_status = "Handshake successful" if handshake_success else f"Handshake failed: {handshake_response}"
    except Exception as e:
        handshake_status = f"Handshake failed: {str(e)}"
    
    return render_template(
        'index.html',
        status="Ready to upload/download file",
        username=session['username'],
        handshake_status=handshake_status
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        if 'file' not in request.files:
            return {"status": "❌ No file selected.", "time": 0, "encrypt_time": 0}, 400

        file = request.files['file']
        if not file or not allowed_file(file.filename):
            return {"status": "❌ Invalid file type. Please upload a .mp3 file.", "time": 0, "encrypt_time": 0}, 400

        simulate_attack = 'simulate_attack' in request.form
        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        client = Client(filepath)
        handshake_success, handshake_response = client.handshake()
        if not handshake_success:
            return {"status": f"❌ Handshake failed: {handshake_response}", "time": 0, "encrypt_time": 0}, 500

        result = client.upload(simulate_attack=simulate_attack)
        if result["status"].startswith("ACK"):
            # Lưu thông tin upload vào session, bao gồm public key và signature đã ký
            session['uploaded_files'][filename] = {
                "session_key": client.crypto.session_key.hex(),
                "metadata": client.uploaded_files.get(filename, {}).get("metadata", {}),
                "signature": base64.b64encode(client.uploaded_files.get(filename, {}).get("signature", b"")).decode(),
                "public_key": client.crypto.public_key.export_key().decode()
            }
            session.modified = True
            logging.debug(f"Session uploaded_files updated: {session['uploaded_files']}")
        return {
            "status": f"{result['status']} (Time: {result['time']:.2f}s)",
            "time": result['time'],
            "encrypt_time": result.get('encrypt_time', 0)
        }, 200
    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        return {"status": f"❌ Error: {str(e)}", "time": 0, "encrypt_time": 0}, 500

@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        if filename not in session.get('uploaded_files', {}):
            logging.error(f"No upload info found for {filename} in session: {session.get('uploaded_files', {})}")
            return {"status": f"❌ NACK: No upload info"}, 400

        file_info = session['uploaded_files'][filename]
        client = Client(None)
        client.crypto = CryptoUtils(session_key=bytes.fromhex(file_info["session_key"]))
        client.server_public_key = client.get_server_public_key()
        client.crypto.public_key = RSA.import_key(file_info["public_key"])  # Public key của client

        # Đảm bảo metadata được gửi đúng
        metadata = file_info.get("metadata", {})
        if not metadata:
            logging.error(f"Metadata is missing or invalid for {filename}: {file_info}")
            return {"status": f"❌ NACK: Invalid metadata"}, 400
        metadata_str = json.dumps(metadata)

        signature = base64.b64decode(file_info["signature"])  # Signature từ upload
        enc_session_key = client.crypto.encrypt_session_key(client.server_public_key)
        packet = {
            "request": "download",
            "metadata": metadata_str,
            "sig": base64.b64encode(signature).decode(),
            "session_key": base64.b64encode(enc_session_key).decode(),
            "public_key": file_info["public_key"]
        }

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client_socket.connect((client.host, client.port))
        packet_data = json.dumps(packet).encode('utf-8')
        length = len(packet_data)
        client_socket.sendall(length.to_bytes(4, 'big'))
        total_sent = 0
        while total_sent < len(packet_data):
            sent = client_socket.send(packet_data[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent
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
            chunk = client_socket.recv(min(client.buffer_size, length - len(response_data)))
            if not chunk:
                break
            response_data += chunk
        response = json.loads(response_data.decode())
        client_socket.close()

        if response["status"] == "ACK":
            metadata = response.get("metadata", {})
            if not isinstance(metadata, dict):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    logging.error(f"Invalid metadata format for {filename}: {metadata}")
                    return {"status": "❌ NACK: Invalid metadata format"}, 400
            # Xác minh chữ ký từ server sử dụng server_public_key
            if not client.crypto.verify_signature(metadata, base64.b64decode(response["sig"]), client.server_public_key):
                logging.error(f"Invalid signature from server for {filename}")
                return {"status": "❌ NACK: Invalid signature from server"}, 400
            computed_hash = client.crypto.compute_hash(
                base64.b64decode(response["nonce"]),
                base64.b64decode(response["cipher"]),
                base64.b64decode(response["tag"])
            )
            if computed_hash != base64.b64decode(response["hash"]):
                return {"status": "❌ NACK: Hash mismatch"}, 400
            decrypt_start = time.time()
            output_path = f"uploads/downloaded_{filename}"
            if client.crypto.decrypt_file(
                base64.b64decode(response["nonce"]),
                base64.b64decode(response["cipher"]),
                base64.b64decode(response["tag"]),
                output_path
            ):
                decrypt_time = time.time() - decrypt_start
                return send_file(output_path, as_attachment=True, download_name=filename)
            else:
                return {"status": "❌ NACK: Tag mismatch"}, 400
        return {"status": f"❌ {response['status']}"}, 400
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        return {"status": f"❌ Error: {str(e)}"}, 500

@app.route('/files')
def list_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('cloud.db')
        c = conn.cursor()
        c.execute('SELECT filename, timestamp, size, hash FROM files')
        files = c.fetchall()
        conn.close()
        return render_template('files.html', files=files, status="List of uploaded files", username=session['username'])
    except Exception as e:
        return render_template('index.html', status=f"❌ Error: {str(e)}", username=session['username'])

@app.route('/logs')
def view_logs():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('cloud.db')
        c = conn.cursor()
        c.execute('SELECT timestamp, event FROM logs ORDER BY timestamp DESC')
        logs = c.fetchall()
        conn.close()
        return render_template('logs.html', logs=logs, status="Communication Logs", username=session['username'])
    except Exception as e:
        # Fix: Thêm handshake_status khi render index.html trong exception handler
        try:
            client = Client(None)
            handshake_success, handshake_response = client.handshake()
            handshake_status = "Handshake successful" if handshake_success else f"Handshake failed: {handshake_response}"
        except:
            handshake_status = "Handshake failed: Connection error"
        
        return render_template('index.html', 
                             status=f"❌ Error: {str(e)}", 
                             username=session['username'],
                             handshake_status=handshake_status)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True, host='0.0.0.0', port=5000)