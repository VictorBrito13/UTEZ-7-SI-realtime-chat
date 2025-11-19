# server.py
# Servidor TCP con sistema de autenticación y exportación de mensajes a Excel

# Importamos las librerías necesarias
import socket           # Para crear sockets TCP y manejar conexiones de red
import threading        # Para manejar múltiples clientes simultáneamente
from datetime import datetime  # Para obtener timestamps de los mensajes
from openpyxl import Workbook # Para crear archivos Excel con los mensajes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidKey
import base64  # Para codificación/decodificación en base64
import hashlib  # Para hash SHA-256
import os       # Para variables de entorno
import json     # Para procesar JSON
from dotenv import load_dotenv  # Para cargar variables de entorno desde archivo
import ssl

# ==================== CARGA DE VARIABLES DE ENTORNO ====================
# Carga las variables desde el archivo .env
load_dotenv()

# ==================== CONFIGURACIÓN DEL SERVIDOR ====================
HOST = os.getenv('SERVER_HOST', '0.0.0.0')  # Usa valor por defecto si no existe
PORT = int(os.getenv('SERVER_PORT', 12346))  # Convierte a entero

# Configuración de RSA desde variables de entorno
RSA_KEY_SIZE = int(os.getenv('RSA_KEY_SIZE', 2048))
RSA_PUBLIC_EXPONENT = int(os.getenv('RSA_PUBLIC_EXPONENT', 65537))

# Generación del par de claves RSA para el servidor
private_key = rsa.generate_private_key(
    public_exponent=RSA_PUBLIC_EXPONENT,
    key_size=RSA_KEY_SIZE
)
public_key = private_key.public_key()

# Serialización de la clave pública para compartirla con los clientes
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("🔑 Par de claves RSA generado correctamente")
print("📤 Clave pública lista para ser compartida con los clientes")

# ==================== CONFIGURACIÓN TLS/SSL ====================
# Rutas de certificado/clave (usar .env para configurarlas)
SERVER_CERT = os.getenv('SERVER_CERT', 'cert.pem')
SERVER_KEY = os.getenv('SERVER_KEY', 'key.pem')
CA_CERT = os.getenv('CA_CERT', '')  # opcional, para verificar clientes o para cliente verificar servidor
REQUIRE_CLIENT_CERT = os.getenv('CLIENT_VERIFY', 'false').lower() in ('1', 'true', 'yes')

# Crear contexto TLS para el servidor
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
try:
    # Cargar certificado y clave del servidor
    ssl_context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    
    # Configurar verificación de cliente
    if REQUIRE_CLIENT_CERT:
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        # Cargar certificado del cliente como CA para verificación
        CLIENT_CERT = os.getenv('CLIENT_CERT', 'client_cert.pem')
        if os.path.exists(CLIENT_CERT):
            ssl_context.load_verify_locations(CLIENT_CERT)
        else:
            print("⚠️ No se encontró el certificado del cliente")
    
    print(f"🔐 SSL context cargado: cert={SERVER_CERT} key={SERVER_KEY} require_client_cert={REQUIRE_CLIENT_CERT}")
except Exception as e:
    print(f"⚠️ No se pudo cargar los certificados TLS: {e}. El servidor seguirá sin TLS.")
    ssl_context = None

# ==================== BASE DE DATOS DE USUARIOS ====================
# Carga la base de datos de usuarios desde las variables de entorno
try:
    USERS_DB = json.loads(os.getenv('USERS_DB', '{}'))
    if not USERS_DB:
        print("⚠️ Advertencia: No se encontraron usuarios en la configuración")
        USERS_DB = {
            "admin": "admin123",  # Usuario por defecto
        }
except json.JSONDecodeError:
    print("❌ Error al cargar la base de datos de usuarios. Usando valores por defecto.")
    USERS_DB = {
        "admin": "admin123",  # Usuario por defecto
    }

# ==================== VARIABLES GLOBALES ====================
# Lista que mantiene los nombres de usuarios actualmente conectados
connected_users = []
# Lock para sincronizar el acceso a la lista de usuarios conectados (thread-safe)
users_lock = threading.Lock()

# Lista para almacenar todos los mensajes recibidos con sus metadatos
mensajes_recibidos = []
# Lock para sincronizar el acceso a la lista de mensajes (thread-safe)
mensajes_lock = threading.Lock()

# Diccionario para almacenar las conexiones activas de los clientes
# Formato: {username: (conn, addr)}
active_connections = {}
# Lock para sincronizar el acceso a las conexiones activas (thread-safe)
connections_lock = threading.Lock()


# ==================== FUNCIONES DE AUTENTICACIÓN ====================

def authenticate_user(username, password):
    """
    Función que autentica a un usuario verificando sus credenciales.

    Args:
        username (str): Nombre de usuario a verificar
        password (str): Contraseña del usuario

    Returns:
        bool: True si las credenciales son válidas, False en caso contrario
    """
    return username in USERS_DB and USERS_DB[username] == password

# ==================== FUNCIONES DE GESTIÓN DE MENSAJES ====================

def guardar_mensaje(username, mensaje):
    """
    Función que guarda un mensaje en la lista de mensajes recibidos con timestamp.

    Args:
        username (str): Nombre del usuario que envió el mensaje
        mensaje (str): Contenido del mensaje

    Nota:
        Usa un lock para asegurar que múltiples hilos no modifiquen la lista simultáneamente
    """
    with mensajes_lock:  # Bloquea el acceso para evitar condiciones de carrera
        mensajes_recibidos.append({
            "usuario": username,
            "mensaje": mensaje,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Formato: 2024-01-15 14:30:25
        })

def exportar_a_excel(nombre_archivo="mensajes_chat.xlsx"):
    """
    Función que exporta todos los mensajes guardados a un archivo Excel.

    Args:
        nombre_archivo (str): Nombre del archivo Excel a generar (por defecto: "mensajes_chat.xlsx")

    Funcionalidad:
        - Crea un nuevo libro de Excel
        - Añade una hoja llamada "Mensajes"
        - Establece las cabeceras: Usuario, Mensaje, Fecha y Hora
        - Añade todos los mensajes guardados
        - Guarda el archivo en el directorio actual

    Nota:
        Usa un lock para leer de forma segura la lista de mensajes
    """
    # Crear un nuevo libro de Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Mensajes"

    # Añadir cabeceras
    ws.append(["Usuario", "Mensaje", "Fecha y Hora"])

    # Añadir todos los mensajes (con lock para thread-safety)
    with mensajes_lock:
        for mensaje in mensajes_recibidos:
            ws.append([mensaje["usuario"], mensaje["mensaje"], mensaje["timestamp"]])

    # Guardar el archivo
    wb.save(nombre_archivo)
    print(f"✅ Archivo Excel '{nombre_archivo}' generado con {len(mensajes_recibidos)} mensajes.")

def cerrar_todas_las_conexiones():
    """
    Función que cierra todas las conexiones activas de clientes.
    Envía un mensaje de cierre del servidor a cada cliente y cierra sus conexiones.
    """
    print("🔌 Cerrando todas las conexiones de clientes...")

    with connections_lock:
        for username, (conn, addr) in active_connections.items():
            try:
                # Enviar mensaje de cierre del servidor
                conn.sendall("SERVER_SHUTDOWN".encode())
                print(f"📤 Notificando cierre a {username} desde {addr}")
            except:
                pass  # Si no se puede enviar, continuamos
            finally:
                try:
                    conn.close()
                    print(f"✅ Conexión cerrada para {username}")
                except:
                    pass  # Si ya está cerrada, continuamos
    
    # Limpiar las listas
    with users_lock:
        connected_users.clear()
    with connections_lock:
        active_connections.clear()
    
    print("✅ Todas las conexiones han sido cerradas.")

# ==================== FUNCIÓN PRINCIPAL DE MANEJO DE CLIENTES ====================

def handle_client(conn, addr):
    """
    Función que maneja la comunicación con un cliente específico.
    Se ejecuta en un hilo separado para cada cliente conectado.
    
    Funcionalidades:
    - Autenticación de usuarios
    - Recepción y procesamiento de mensajes
    - Gestión de sesiones (login/logout)
    - Prevención de suplantación de identidad
    
    Args:
        conn: Objeto socket de conexión con el cliente
        addr: Tupla con la IP y puerto del cliente (ej: ('127.0.0.1', 54321))
    """
    print(f"🔗 Nueva conexión desde {addr}")
    current_user = None  # Variable para rastrear el usuario autenticado de esta conexión
    
    # Bucle principal para recibir y procesar mensajes del cliente
    while True:
        try:
            # Recibimos hasta 1024 bytes de datos del cliente
            data = conn.recv(1024)
            if not data:
                break  # El cliente cerró la conexión
            
            # Decodificamos los bytes a string
            message = data.decode().strip()
            
            # ==================== PROCESAMIENTO DE CLAVE PÚBLICA ====================
            if message == "REQUEST_PUBLIC_KEY":
                # Enviar la clave pública al cliente
                conn.sendall(b"PUBLIC_KEY:" + public_pem)
                continue

            # ==================== PROCESAMIENTO DE LOGIN ====================
            elif message.startswith("LOGIN:"):
                # Formato esperado: "LOGIN:username:password"
                parts = message.split(":", 2)
                if len(parts) == 3:
                    _, username, password = parts
                    
                    # Usamos lock para modificar la lista de usuarios conectados de forma segura
                    with users_lock:
                        if username in connected_users:
                            # Usuario ya está conectado desde otra sesión
                            conn.sendall("LOGIN_FAIL".encode())
                            print(f"❌ Intento de login fallido para {username} desde {addr}: Usuario ya conectado")
                        else:
                            # Verificamos las credenciales
                            if authenticate_user(username, password):
                                current_user = username
                                connected_users.append(username)
                                # Registrar la conexión activa
                                with connections_lock:
                                    active_connections[username] = (conn, addr)
                                conn.sendall("LOGIN_OK".encode())
                                print(f"✅ Login exitoso: {username} desde {addr}")
                                print(f"👥 Usuarios conectados: {connected_users}")
                            else:
                                conn.sendall("LOGIN_FAIL".encode())
                                print(f"❌ Login fallido para {username} desde {addr}: Credenciales incorrectas")
                    continue
            
            # ==================== PROCESAMIENTO DE LOGOUT ====================
            elif message.startswith("LOGOUT:"):
                # Formato esperado: "LOGOUT:username"
                parts = message.split(":", 1)
                if len(parts) == 2 and current_user:
                    username = parts[1]
                    if username == current_user:  # Verificamos que sea el usuario autenticado
                        with users_lock:
                            if username in connected_users:
                                connected_users.remove(username)
                        # Remover la conexión activa
                        with connections_lock:
                            if username in active_connections:
                                del active_connections[username]
                        print(f"👋 Logout: {username} desde {addr}")
                        print(f"👥 Usuarios conectados: {connected_users}")
                break  # Terminamos el bucle y cerramos la conexión
            
            # ==================== PROCESAMIENTO DE MENSAJES ====================
            elif message.startswith("MESSAGE:"):
                # Formato esperado: "MESSAGE:username:mensaje_cifrado"
                parts = message.split(":", 2)
                if len(parts) == 3 and current_user:
                    _, username, encrypted_msg = parts
                    if username == current_user:  # Verificamos que sea el usuario autenticado
                        try:
                            print(f"\n🔐 Mensaje cifrado recibido (base64): {encrypted_msg}")
                            # Decodificamos el mensaje cifrado de base64
                            encrypted_msg = base64.b64decode(encrypted_msg.encode())
                            print(f"🔐 Mensaje cifrado (bytes): {encrypted_msg}")
                            
                            # Desciframos el mensaje usando RSA con SHA-256
                            decrypted_msg = private_key.decrypt(
                                encrypted_msg,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            
                            # Separamos el hash y el mensaje
                            msg_hash = decrypted_msg[:32]  # SHA-256 produce 32 bytes
                            msg = decrypted_msg[32:].decode()
                            
                            # Verificamos la integridad del mensaje
                            calculated_hash = hashlib.sha256(msg.encode()).digest()
                            if msg_hash != calculated_hash:
                                raise InvalidKey("¡La verificación del hash falló!")
                            
                            print(f"🔓 Mensaje descifrado: {msg}")
                            print(f"🔒 Hash SHA-256: {msg_hash.hex()}")
                            print(f"✅ Verificación de integridad: OK")
                            print(f"💬 [{current_user}] {msg}")
                            guardar_mensaje(current_user, msg)  # Guardamos el mensaje con timestamp
                        except Exception as e:
                            print(f"❌ Error al descifrar mensaje de {current_user}: {e}")
                    else:
                        print(f"⚠ Intento de suplantación: {username} != {current_user}")
                continue
            
            # ==================== MENSAJE NO RECONOCIDO ====================
            print(f"⚠ Mensaje sin formato válido desde {addr}: {message}")
            
        except ConnectionResetError:
            # El cliente cerró abruptamente la conexión
            break
        except Exception as e:
            print(f"❌ Error procesando mensaje desde {addr}: {e}")
            break
    
    # ==================== LIMPIEZA AL DESCONECTAR ====================
    # Removemos el usuario de la lista de conectados si estaba autenticado
    if current_user:
        with users_lock:
            if current_user in connected_users:
                connected_users.remove(current_user)
        # Remover la conexión activa
        with connections_lock:
            if current_user in active_connections:
                del active_connections[current_user]
        print(f"👥 Usuarios conectados: {connected_users}")
    
    print(f"🔌 Desconectado {current_user or 'usuario no autenticado'} desde {addr}")
    conn.close()  # Cerramos la conexión

# ==================== FUNCIÓN DE COMANDOS DE ADMINISTRACIÓN ====================

def admin_commands():
    """
    Función que maneja los comandos de administración del servidor.
    Se ejecuta en un hilo separado para no bloquear las conexiones de clientes.
    
    Comandos disponibles:
    - exportar_excel: Exporta todos los mensajes a un archivo Excel
    - salir: Muestra mensaje de cierre (el servidor debe detenerse manualmente)
    """
    while True:
        cmd = input()  # Esperamos comandos del administrador
        
        if cmd.strip().lower() == "exportar_excel":
            # Exportar todos los mensajes a Excel
            exportar_a_excel()
        elif cmd.strip().lower() == "salir":
            # Cerrar el servidor completamente
            print("🛑 Cerrando servidor...")
            cerrar_todas_las_conexiones()  # Cerrar todas las conexiones de clientes
            import os
            os._exit(0)  # Cierra el servidor completamente

# ==================== FUNCIÓN PRINCIPAL DEL SERVIDOR ====================

def main():
    """
    Función principal que configura e inicia el servidor TCP.
    
    Funcionalidades:
    - Configura el socket del servidor
    - Muestra información de usuarios disponibles
    - Inicia hilo para comandos de administración
    - Acepta conexiones de clientes en bucle infinito
    - Crea un hilo separado para cada cliente conectado
    """
    print("🚀 Iniciando servidor con sistema de autenticación...")
    print(f"📡 Servidor escuchando en {HOST}:{PORT}")
    print("\n👤 Usuarios disponibles para login:")
    
    # Mostrar todos los usuarios y contraseñas disponibles
    """
    for username, password in USERS_DB.items():
        print(f"   • {username} : {password}")
    print("\n" + "="*50)
    """
    
    # ==================== CONFIGURACIÓN DEL SOCKET ====================
    # Verificar si el puerto está en uso
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        test_sock.bind((HOST, PORT))
        test_sock.close()
    except OSError:
        test_sock.close()
        print(f"❌ Error: El puerto {PORT} ya está en uso.")
        print(f"💡 Soluciones:")
        print(f"   1. Cierra el proceso anterior que está usando el puerto {PORT}")
        print(f"   2. Cambia el puerto en el archivo .env (SERVER_PORT)")
        print(f"   3. En Windows, usa: netstat -ano | findstr :{PORT} para encontrar el proceso")
        print(f"      Luego cierra el proceso con: taskkill /PID <PID> /F")
        return
    
    # Crear socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Permitir reutilizar la dirección si el socket está en TIME_WAIT
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Asociar el socket a la dirección IP y puerto
        server.bind((HOST, PORT))
        
        # Poner el socket en modo escucha para aceptar conexiones
        server.listen()
        
        print(f"✅ Servidor iniciado correctamente!")
        print("🔗 Esperando conexiones de clientes...")
        print("💡 Comandos disponibles: 'exportar_excel', 'salir'\n")
    except OSError as e:
        if e.errno == 10048 or "already in use" in str(e).lower():
            print(f"❌ Error: El puerto {PORT} ya está en uso.")
            print(f"💡 Soluciones:")
            print(f"   1. Cierra el proceso anterior: netstat -ano | findstr :{PORT}")
            print(f"   2. Cambia el puerto en el archivo .env (SERVER_PORT)")
        else:
            print(f"❌ Error al iniciar el servidor: {e}")
        server.close()
        return
    
    # ==================== HILO DE ADMINISTRACIÓN ====================
    # Iniciar hilo separado para comandos de administración
    # daemon=True permite que el programa termine aunque este hilo esté activo
    threading.Thread(target=admin_commands, daemon=True).start()
    
    # ==================== BUCLE PRINCIPAL ====================
    # Bucle infinito para aceptar conexiones de clientes
    while True:
            # Esperar a que un cliente se conecte (esto bloquea hasta que llega una conexión)
            conn, addr = server.accept()

            # Si tenemos contexto TLS, envolver la conexión para asegurar la comunicación
            conn_to_use = conn
            if ssl_context is not None:
                try:
                    ssl_conn = ssl_context.wrap_socket(conn, server_side=True)
                    conn_to_use = ssl_conn
                    print(f"🔐 Conexión TLS establecida con {addr}")
                except ssl.SSLError as e:
                    print(f"❌ Error TLS al envolver conexión desde {addr}: {e}")
                    try:
                        conn.close()
                    except:
                        pass
                    continue

            # Crear un nuevo hilo para manejar este cliente específico
            # target: función que ejecutará el hilo
            # args: argumentos que se pasan a la función
            # daemon=True: el hilo se cierra cuando termina el programa principal
            thread = threading.Thread(target=handle_client, args=(conn_to_use, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()