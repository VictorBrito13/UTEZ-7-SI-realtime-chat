# client.py
# Cliente TCP con sistema de autenticación y comunicación bidireccional

# ==================== IMPORTACIONES ====================
import socket      # Para crear sockets TCP y manejar conexiones de red
import threading   # Para recibir mensajes del servidor en un hilo separado
import sys         # Para funcionalidades del sistema
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64      # Para codificación/decodificación en base64
import hashlib    # Para hash SHA-256
import os         # Para variables de entorno
from dotenv import load_dotenv  # Para cargar variables de entorno
import ssl

# ==================== CARGA DE VARIABLES DE ENTORNO ====================
# Carga las variables desde el archivo .env
load_dotenv()

# ==================== CONFIGURACIÓN DEL CLIENTE ====================
HOST = os.getenv('CLIENT_HOST', '127.0.0.1')  # Usa valor por defecto si no existe
PORT = int(os.getenv('CLIENT_PORT', 12346))   # Convierte a entero

# Variable para almacenar la clave pública del servidor
server_public_key = None

# ==================== FUNCIÓN DE RECEPCIÓN DE MENSAJES ====================

def receive_messages(sock):
    """
    Función que se ejecuta en un hilo separado para recibir mensajes del servidor.
    Permite recibir mensajes mientras el usuario puede escribir otros.
    
    Esta función está diseñada para comunicación bidireccional, pero está comentada
    en el código principal. Para activarla, descomenta la línea correspondiente en main().
    
    Args:
        sock: Socket conectado al servidor
        
    Funcionalidad:
    - Escucha continuamente mensajes del servidor
    - Muestra los mensajes recibidos en la consola
    - Termina si se pierde la conexión
    - Maneja el mensaje de cierre del servidor
    """
    while True:
        try:
            # Recibimos hasta 1024 bytes de datos del servidor
            data = sock.recv(1024)
            
            # Si no hay datos, el servidor cerró la conexión
            if not data:
                print("Desconectado del servidor.")
                break
            
            # Decodificamos el mensaje recibido
            message = data.decode().strip()
            
            # Verificar si es un mensaje de cierre del servidor
            if message == "SERVER_SHUTDOWN":
                print("\n🛑 El servidor se está cerrando. Desconectando...")
                import os
                os._exit(0)  # Termina el cliente inmediatamente
                
            # Mostrar otros mensajes
            print(message)
            
        except:
            # Cualquier error (conexión perdida, etc.) termina el hilo
            break

# ==================== FUNCIÓN DE AUTENTICACIÓN ====================

def login(sock):
    """
    Función que maneja el proceso de login del cliente.
    
    Esta función implementa un sistema de autenticación que:
    - Solicita credenciales al usuario
    - Valida que no estén vacías
    - Envía las credenciales al servidor
    - Espera la respuesta de autenticación
    - Permite reintentos en caso de fallo
    
    Args:
        sock: Socket conectado al servidor
        
    Returns:
        str: Nombre de usuario si el login es exitoso, None si falla
        
    Protocolo de comunicación:
        Cliente -> Servidor: "LOGIN:username:password"
        Servidor -> Cliente: "LOGIN_OK" o "LOGIN_FAIL"
    """
    print("\n=== SISTEMA DE LOGIN ===")
    
    # Bucle para permitir reintentos en caso de credenciales incorrectas
    while True:
        try:
            # ==================== SOLICITUD DE CREDENCIALES ====================
            # Solicitamos el nombre de usuario
            username = input("Ingresa tu nombre de usuario: ").strip()
            
            # Validamos que el nombre no esté vacío
            if not username:
                print("❌ El nombre de usuario no puede estar vacío.")
                continue
            
            # Solicitamos la contraseña
            password = input("Ingresa tu contraseña: ").strip()
            
            # Validamos que la contraseña no esté vacía
            if not password:
                print("❌ La contraseña no puede estar vacía.")
                continue
            
            # ==================== ENVÍO DE CREDENCIALES ====================
            # Enviamos las credenciales al servidor en el formato esperado
            # Formato: "LOGIN:username:password"
            login_data = f"LOGIN:{username}:{password}"
            sock.sendall(login_data.encode())
            
            # ==================== RESPUESTA DEL SERVIDOR ====================
            # Esperamos la respuesta del servidor (bloquea hasta recibir respuesta)
            response = sock.recv(1024).decode().strip()
            
            if response == "LOGIN_OK":
                print(f"✅ Login exitoso! Bienvenido, {username}")
                return username  # Retornamos el username para uso posterior
            elif response == "LOGIN_FAIL":
                print("❌ Credenciales incorrectas. Intenta de nuevo.")
                # Continuamos el bucle para permitir reintento
            else:
                print(f"❌ Error del servidor: {response}")
                
        except Exception as e:
            print(f"❌ Error durante el login: {e}")
            return None  # En caso de error, retornamos None

# ==================== FUNCIÓN PRINCIPAL DEL CLIENTE ====================

def main():
    """
    Función principal que configura y ejecuta el cliente TCP.
    
    Flujo de funcionamiento:
    1. Establece conexión con el servidor
    2. Realiza proceso de autenticación (login)
    3. Permite enviar mensajes al servidor
    4. Maneja la desconexión ordenada
    5. Gestiona errores de conexión
    
    Características:
    - Sistema de autenticación obligatorio
    - Envío de mensajes con formato estructurado
    - Manejo robusto de errores
    - Desconexión ordenada con notificación al servidor
    """
    print("🔗 Conectando al servidor...")
    
    # ==================== CONFIGURACIÓN DEL SOCKET TLS ====================
    # Crear contexto TLS para el cliente según configuración
    CLIENT_VERIFY = os.getenv('CLIENT_VERIFY', 'true').lower() in ('1','true','yes')
    SERVER_CERT = os.getenv('SERVER_CERT', 'cert.pem')
    CLIENT_CERT = os.getenv('CLIENT_CERT', 'client_cert.pem')
    CLIENT_KEY = os.getenv('CLIENT_KEY', 'client_key.pem')

    # Crear contexto SSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Cargar certificado del servidor para verificación
    if os.path.exists(SERVER_CERT):
        context.load_verify_locations(SERVER_CERT)
    else:
        print("⚠️ No se encontró el certificado del servidor")
    
    # Cargar certificado y clave del cliente
    if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    else:
        print("⚠️ No se encontraron los certificados del cliente")
    
    if not CLIENT_VERIFY:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Envolver el socket con TLS (usa server_hostname para verificación si CLIENT_VERIFY)
    try:
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=HOST if CLIENT_VERIFY else None)
        ssl_sock.connect((HOST, PORT))
        sock = ssl_sock
        print("✅ Conectado al servidor exitosamente (TLS)")
    except Exception as e:
        print(f"❌ No se pudo establecer conexión TLS con el servidor: {e}")
        raw_sock.close()
        return

    try:
        # Solicitamos la clave pública del servidor
        print("🔑 Solicitando clave pública del servidor...")
        sock.sendall("REQUEST_PUBLIC_KEY".encode())
        response = sock.recv(4096)  # Aumentamos el buffer para recibir la clave
        
        if response.startswith(b"PUBLIC_KEY:"):
            # Procesamos la clave pública recibida
            global server_public_key
            public_key_pem = response[11:]  # Removemos el prefijo "PUBLIC_KEY:"
            server_public_key = serialization.load_pem_public_key(public_key_pem)
            print("✅ Clave pública del servidor recibida")
        else:
            print("❌ Error al recibir la clave pública del servidor")
            return
        
        # ==================== PROCESO DE AUTENTICACIÓN ====================
        # Realizamos el proceso de login
        username = login(sock)
        
        # Si el login falla, terminamos la conexión
        if not username:
            print("❌ No se pudo completar el login. Cerrando conexión.")
            return
        
        print(f"\n💬 Ahora puedes enviar mensajes como '{username}':")
        print("💡 Escribe 'salir' para desconectarte\n")

        # ==================== HILO DE RECEPCIÓN DE MENSAJES DE CONTROL ====================
        # Hilo para recibir mensajes de control del servidor (como cierre del servidor)
        # Esto es necesario para manejar el cierre ordenado del servidor
        threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

        # ==================== BUCLE PRINCIPAL DE ENVÍO ====================
        # Bucle principal para enviar mensajes
        while True:
            # Esperamos a que el usuario escriba un mensaje
            # El prompt muestra el nombre de usuario para mayor claridad
            msg = input(f"[{username}] ")
            
            # ==================== PROCESAMIENTO DE COMANDOS ====================
            # Si el usuario escribe "salir", terminamos la conexión
            if msg.lower() == "salir":
                # Enviamos mensaje de logout al servidor para notificar la desconexión
                logout_msg = f"LOGOUT:{username}"
                sock.sendall(logout_msg.encode())
                break
                
            # ==================== ENVÍO DE MENSAJES ====================
            try:
                if not server_public_key:
                    print("❌ Error: No se ha recibido la clave pública del servidor")
                    continue

                # Calculamos el hash SHA-256 del mensaje
                msg_hash = hashlib.sha256(msg.encode()).digest()
                
                # Combinamos el hash y el mensaje
                combined_message = msg_hash + msg.encode()
                
                # Ciframos el mensaje combinado con RSA
                encrypted_msg = server_public_key.encrypt(
                    combined_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Codificamos en base64 para transmisión
                encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode()
                
                print(f"\n📤 Enviando mensaje...")
                print(f"� Mensaje original: {msg}")
                print(f"🔒 Hash SHA-256: {msg_hash.hex()}")
                print(f"�🔐 Mensaje cifrado (base64): {encrypted_msg_b64}")
                
                # Enviamos el mensaje al servidor con formato estructurado
                formatted_msg = f"MESSAGE:{username}:{encrypted_msg_b64}"
                sock.sendall(formatted_msg.encode())
            except Exception as e:
                print(f"❌ Error al cifrar el mensaje: {e}")
            
    # ==================== MANEJO DE ERRORES ====================
    except ConnectionRefusedError:
        print("❌ Error: No se pudo conectar al servidor.")
        print("💡 Asegúrate de que el servidor esté ejecutándose.")
    except KeyboardInterrupt:
        # Si el usuario presiona Ctrl+C, terminamos silenciosamente
        print("\n👋 Saliendo...")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
    finally:
        # ==================== LIMPIEZA ====================
        # Siempre cerramos la conexión, sin importar cómo termine el programa
        sock.close()
        print("🔌 Conexión cerrada.")

# ==================== PUNTO DE ENTRADA DEL PROGRAMA ====================
# Solo ejecutamos main() si este archivo se ejecuta directamente
# (no si se importa como módulo)
if __name__ == "__main__":
  main()