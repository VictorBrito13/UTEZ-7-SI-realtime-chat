import asyncio
import websockets
import json
import os
import jwt
import time
import hashlib
import socket
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from pathlib import Path

# ==================== CARGA DE VARIABLES DE ENTORNO ====================
load_dotenv()

# ==================== CONFIGURACIÓN BÁSICA ====================
# Render.com provides PORT environment variable, fallback to SERVER_PORT or default
HOST = os.getenv('SERVER_HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', os.getenv('SERVER_PORT', 12345)))

JWT_SECRET = os.getenv('API_JWT_SECRET', 'tu_secreto_jwt_cambiar')
JWT_ALG = "HS256"
JWT_EXP = 3600  # 1 hora

# Configuración de firma de PDFs
SIGNATURE_TOKEN_EXPIRY = int(os.getenv('SIGNATURE_TOKEN_EXPIRY', 1800))
SIGNING_SECRET = os.getenv('SIGNING_SECRET', 'super-secret-key-change-me')
PDF_FILE_ID = os.getenv('PDF_FILE_ID', '')
PDF_LOCAL_PATH = os.getenv('PDF_LOCAL_PATH', 'test_document.pdf')  # Alternativa: PDF local
PDF_UPLOAD_DIR = os.getenv('PDF_UPLOAD_DIR', './pdf_uploads')

# Crear directorio de PDFs si no existe
Path(PDF_UPLOAD_DIR).mkdir(exist_ok=True)

# ⚠️ PARA PROBAR: IGNORAMOS .env Y FIJAMOS LOS USUARIOS AQUÍ
USERS_DB = {
    "alice": "pass123",
    "bob": "pass456",
    "admin": "admin123",
}

print("👤 Usuarios válidos del servidor:")
for u, p in USERS_DB.items():
    print(f"   - {u} / {p}")

# ==================== GENERACIÓN / CARGA DE CLAVES RSA ====================
KEY_PRIV_FILE = os.getenv('RSA_PRIVATE_KEY', 'rsa_private_key.pem')
KEY_PUB_FILE = os.getenv('RSA_PUBLIC_KEY', 'rsa_public_key.pem')


def load_or_generate_rsa_keys(priv_path=KEY_PRIV_FILE, pub_path=KEY_PUB_FILE):
    """Carga claves RSA desde disco si existen; si no, las genera y las guarda.
    Retorna (private_key, public_key, public_pem_str)
    """
    priv_p = Path(priv_path)
    pub_p = Path(pub_path)

    # Intentar cargar si ambos archivos existen
    if priv_p.exists() and pub_p.exists():
        try:
            with open(priv_path, 'rb') as f:
                priv_data = f.read()
                private_key = serialization.load_pem_private_key(
                    priv_data,
                    password=None
                )

            with open(pub_path, 'rb') as f:
                pub_data = f.read()
                public_key = serialization.load_pem_public_key(pub_data)

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            print(f"🔑 Claves RSA cargadas desde archivos: {priv_path}, {pub_path}")
            return private_key, public_key, public_pem
        except Exception as e:
            print(f"⚠️ Error cargando claves RSA desde disco: {e}. Se regenerarán las claves.")

    # Generar nuevas claves
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Intentar escribir a disco (no bloqueante si falla)
    try:
        with open(priv_path, 'wb') as f:
            f.write(priv_bytes)
        with open(pub_path, 'wb') as f:
            f.write(pub_bytes)
        print(f"✅ Claves RSA generadas y guardadas: {priv_path}, {pub_path}")
    except Exception as e:
        print(f"⚠️ No se pudo guardar claves en disco: {e} (continuando con claves en memoria)")

    public_pem = pub_bytes.decode()
    print("🔑 Par de claves RSA generado en memoria")
    return private_key, public_key, public_pem


# Cargar o generar claves RSA persistentes
private_key, public_key, public_pem = load_or_generate_rsa_keys()

# ==================== ROOM COMPARTIDO ====================
class ChatRoom:
    def __init__(self):
        self.clients = {}  # {websocket: username}
        self.messages = []  # historial de mensajes

    async def broadcast(self, message, sender=None):
        """Envía un mensaje a todos los clientes conectados"""
        if not self.clients:
            return
        disconnected = set()
        for ws in list(self.clients):
            try:
                await ws.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(ws)

        # Limpiar desconexiones
        for ws in disconnected:
            if ws in self.clients:
                del self.clients[ws]

    def add_client(self, ws, username):
        """Añade un cliente al room"""
        self.clients[ws] = username

    def remove_client(self, ws):
        """Remueve un cliente del room"""
        if ws in self.clients:
            del self.clients[ws]

    def get_users(self):
        """Retorna lista de usuarios conectados"""
        return list(self.clients.values())


room = ChatRoom()

# ==================== FUNCIONES DE AUTENTICACIÓN ====================
def verify_credentials(username, password):
    """Verifica credenciales del usuario"""
    print(f"🔍 Verificando credenciales: {username} / {password}")
    print(f"📚 USERS_DB actual: {USERS_DB}")
    return username in USERS_DB and USERS_DB[username] == password


def generate_jwt_token(username):
    """Genera un token JWT"""
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + JWT_EXP
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token


def verify_jwt_token(token):
    """Verifica y decodifica un token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.PyJWTError as e:
        print(f"❌ Error al verificar JWT: {e}")
        return None

# ==================== FUNCIONES DE FIRMA DE PDFs ====================
def generate_signature_token(username):
    """Genera un token temporal para firmar PDFs"""
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + SIGNATURE_TOKEN_EXPIRY,
        "purpose": "pdf_signature"
    }
    token = jwt.encode(payload, SIGNING_SECRET, algorithm="HS256")
    return token


def verify_signature_token(token, username=None):
    """Verifica y decodifica un token de firma de PDF"""
    try:
        payload = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])
        if payload.get("purpose") != "pdf_signature":
            return None
        if username and payload.get("sub") != username:
            return None
        return payload
    except jwt.PyJWTError as e:
        print(f"❌ Error al verificar token de firma: {e}")
        return None


def download_pdf_from_drive(file_id):
    """Descargar PDF desde Google Drive sin autenticación (archivo compartido)"""
    try:
        if not file_id:
            print("❌ PDF_FILE_ID no configurado en .env")
            return None
        
        # URL de descarga directa de Google Drive (con confirm=no_antivirus para evitar confirmación)
        download_url = f"https://drive.google.com/uc?export=download&id={file_id}&confirm=no_antivirus"
        
        print(f"📥 Descargando PDF desde Google Drive: {file_id}")
        print(f"📥 URL: {download_url}")
        
        # Agregar headers para simular un navegador
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(download_url, timeout=10, headers=headers, allow_redirects=True)
        response.raise_for_status()
        
        # Validar que sea un PDF (no HTML)
        if response.headers.get('content-type', '').startswith('text/html'):
            print("❌ Google Drive devolvió HTML en lugar de PDF. El archivo puede no ser compartido o el ID es inválido.")
            print(f"   Content-Type: {response.headers.get('content-type')}")
            print(f"   Response preview: {response.text[:200]}")
            return None
        
        print(f"✅ PDF descargado exitosamente ({len(response.content)} bytes)")
        return response.content
    except requests.RequestException as e:
        print(f"❌ Error descargando PDF desde Google Drive: {e}")
        return None


def load_pdf_from_local_file(pdf_path):
    """Cargar PDF desde un archivo local"""
    try:
        if not pdf_path or not os.path.exists(pdf_path):
            print(f"❌ Archivo PDF no encontrado: {pdf_path}")
            return None
        
        with open(pdf_path, 'rb') as f:
            pdf_bytes = f.read()
        
        print(f"✅ PDF cargado desde archivo local: {pdf_path} ({len(pdf_bytes)} bytes)")
        return pdf_bytes
    except Exception as e:
        print(f"❌ Error cargando PDF local: {e}")
        return None


def save_signed_pdf(username, pdf_base64, timestamp):
    """Guarda un PDF firmado en el servidor"""
    try:
        # Decodificar base64
        pdf_bytes = base64.b64decode(pdf_base64)
        
        # Crear nombre de archivo único
        filename = f"signed_{username}_{int(time.time())}.pdf"
        filepath = Path(PDF_UPLOAD_DIR) / filename
        
        # Guardar archivo
        with open(filepath, "wb") as f:
            f.write(pdf_bytes)
        
        # Registrar en metadatos
        registry_file = Path(PDF_UPLOAD_DIR) / "signatures_registry.json"
        registry = {}
        if registry_file.exists():
            with open(registry_file, "r") as f:
                registry = json.load(f)
        
        registry[filename] = {
            "signed_by": username,
            "timestamp": timestamp,
            "pdf_hash": hashlib.sha256(pdf_bytes).hexdigest()
        }
        
        with open(registry_file, "w") as f:
            json.dump(registry, f, indent=2)
        
        print(f"✅ PDF firmado guardado: {filename}")
        return filename
    except Exception as e:
        print(f"❌ Error guardando PDF firmado: {e}")
        return None

# ==================== FUNCIONES DE CIFRADO ====================
def decrypt_message(encrypted_msg):
    """Descifra un mensaje RSA + SHA-256"""
    try:
        encrypted_msg = base64.b64decode(encrypted_msg.encode())

        decrypted_msg = private_key.decrypt(
            encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Separar hash y mensaje
        msg_hash = decrypted_msg[:32]  # SHA-256 produce 32 bytes
        msg = decrypted_msg[32:].decode()

        # Verificar integridad
        calculated_hash = hashlib.sha256(msg.encode()).digest()
        if msg_hash != calculated_hash:
            return None

        return msg
    except Exception as e:
        print(f"❌ Error al descifrar mensaje: {e}")
        return None

# ==================== MANEJADOR DE CONEXIÓN ====================
async def handler(websocket):
    """Manejador principal de WebSocket"""
    username = None

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                action = data.get("action")

                # ==================== ACCIÓN: LOGIN ====================
                if action == "login":
                    user = data.get("username")
                    password = data.get("password")

                    if verify_credentials(user, password):
                        username = user
                        token = generate_jwt_token(username)
                        room.add_client(websocket, username)

                        print(f"✅ {username} autenticado correctamente")

                        # Responder con token y public key
                        await websocket.send(json.dumps({
                            "type": "login_success",
                            "token": token,
                            "public_key": public_pem,
                            "message": f"Bienvenido {username}"
                        }))

                        # Notificar a otros usuarios
                        await room.broadcast({
                            "type": "user_joined",
                            "username": username,
                            "users_online": room.get_users(),
                            "timestamp": datetime.now().isoformat()
                        })
                    else:
                        print(f"❌ Login fallido para {user}")
                        await websocket.send(json.dumps({
                            "type": "login_failed",
                            "message": "Credenciales inválidas"
                        }))

                # ==================== ACCIÓN: ENVIAR MENSAJE ====================
                elif action == "send_message":
                    if not username:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "No autenticado"
                        }))
                        continue

                    token = data.get("token")
                    encrypted_msg = data.get("message")
                    encrypted_flag = data.get("encrypted", False)

                    # Verificar token
                    payload = verify_jwt_token(token)
                    if not payload or payload.get("sub") != username:
                        print(f"❌ Token inválido para {username}")
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "Token inválido"
                        }))
                        continue

                    # Procesar mensaje según bandera encrypted
                    if encrypted_flag and encrypted_msg:
                        decrypted_msg = decrypt_message(encrypted_msg)
                        if decrypted_msg is None:
                            print(f"❌ Falló descifrado RSA-OAEP de {username}")
                            await websocket.send(json.dumps({
                                "type": "error",
                                "message": "Failed to decrypt message"
                            }))
                            continue
                        print(f"✅ RSA-OAEP descifrado: [{username}] {decrypted_msg}")
                    else:
                        decrypted_msg = encrypted_msg if encrypted_msg else data.get("message", "")
                        print(f"📝 Mensaje en texto plano de {username}: {decrypted_msg}")

                    print(f"💬 [{username}] {decrypted_msg}")

                    await room.broadcast({
                        "type": "message",
                        "username": username,
                        "message": decrypted_msg,
                        "timestamp": datetime.now().isoformat()
                    })

                # ==================== ACCIÓN: GET USERS ====================
                elif action == "get_users":
                    if not username:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "No autenticado"
                        }))
                        continue

                    await websocket.send(json.dumps({
                        "type": "users_list",
                        "users": room.get_users(),
                        "count": len(room.get_users())
                    }))

                # ==================== ACCIÓN: LOGOUT ====================
                elif action == "logout":
                    if username:
                        room.remove_client(websocket)
                        await room.broadcast({
                            "type": "user_left",
                            "username": username,
                            "users_online": room.get_users(),
                            "timestamp": datetime.now().isoformat()
                        })
                        print(f"👋 {username} desconectado")
                        username = None

                # ==================== ACCIÓN: REQUEST SIGNATURE TOKEN ====================
                elif action == "request_signature_token":
                    if not username:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "No autenticado"
                        }))
                        continue

                    sig_token = generate_signature_token(username)
                    
                    # Intentar cargar PDF (primero local, luego Google Drive)
                    pdf_bytes = None
                    
                    # Opción 1: Cargar desde archivo local
                    if os.path.exists(PDF_LOCAL_PATH):
                        pdf_bytes = load_pdf_from_local_file(PDF_LOCAL_PATH)
                    
                    # Opción 2: Descargar desde Google Drive
                    if not pdf_bytes and PDF_FILE_ID:
                        pdf_bytes = download_pdf_from_drive(PDF_FILE_ID)
                    
                    if pdf_bytes:
                        # Convertir a base64 para enviar al cliente
                        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
                        
                        await websocket.send(json.dumps({
                            "type": "signature_token",
                            "token": sig_token,
                            "pdf_base64": pdf_base64,
                            "expires_in": SIGNATURE_TOKEN_EXPIRY
                        }))
                        print(f"🔑 Token de firma generado para {username}")
                    else:
                        await websocket.send(json.dumps({
                            "type": "signature_error",
                            "message": "No se pudo cargar el PDF (ni local ni desde Google Drive)"
                        }))

                # ==================== ACCIÓN: SUBMIT SIGNED PDF ====================
                elif action == "submit_signed_pdf":
                    sig_token = data.get("token")
                    pdf_base64 = data.get("pdf_base64")
                    timestamp = data.get("timestamp")
                    signed_by = data.get("signed_by")

                    # Verificar token de firma
                    payload = verify_signature_token(sig_token, signed_by)
                    if not payload:
                        print(f"❌ Token de firma inválido para {signed_by}")
                        await websocket.send(json.dumps({
                            "type": "signature_error",
                            "message": "Token de firma inválido o expirado"
                        }))
                        continue

                    # Guardar PDF
                    if pdf_base64 and timestamp:
                        filename = save_signed_pdf(signed_by, pdf_base64, timestamp)
                        if filename:
                            await websocket.send(json.dumps({
                                "type": "signature_success",
                                "message": f"PDF firmado guardado correctamente",
                                "filename": filename
                            }))
                            # Notificar a otros usuarios
                            await room.broadcast({
                                "type": "pdf_signed",
                                "message": f"✅ {signed_by} ha firmado el documento",
                                "username": signed_by,
                                "timestamp": timestamp
                            })
                        else:
                            await websocket.send(json.dumps({
                                "type": "signature_error",
                                "message": "Error guardando PDF firmado"
                            }))
                    else:
                        await websocket.send(json.dumps({
                            "type": "signature_error",
                            "message": "Datos incompletos"
                        }))

            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "JSON inválido"
                }))
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"❌ Error procesando mensaje: {e}")
                try:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Error interno del servidor"
                    }))
                except:
                    try:
                        await websocket.close(code=1011, reason="internal error")
                    except:
                        pass

    except websockets.exceptions.ConnectionClosed:
        if username:
            room.remove_client(websocket)
            await room.broadcast({
                "type": "user_left",
                "username": username,
                "users_online": room.get_users(),
                "timestamp": datetime.now().isoformat()
            })
            print(f"👋 {username} desconectado (conexión cerrada)")

# ==================== INICIO DEL SERVIDOR ====================
async def main():
    print("🚀 Iniciando servidor WebSocket SIN SSL (desarrollo)...")
    print(f"📡 Escuchando en ws://{HOST}:{PORT}")

    # Verificar si el puerto está en uso
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((HOST, PORT))
        sock.close()
    except OSError:
        sock.close()
        print(f"❌ Error: El puerto {PORT} ya está en uso.")
        print(f"💡 Soluciones:")
        print(f"   1. Cierra el proceso anterior que está usando el puerto {PORT}")
        print(f"   2. Cambia el puerto en el archivo .env (SERVER_PORT)")
        return

    try:
        async with websockets.serve(
            handler,
            HOST,
            PORT,
            ping_interval=20,
            ping_timeout=20
        ):
            print(f"✅ Servidor WebSocket activo en ws://{HOST}:{PORT}")
            await asyncio.Future()  # run forever
    except OSError as e:
        print(f"❌ Error al iniciar el servidor: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
