class ChatClient {
  constructor(serverUrl = "wss://localhost:12345") {
    this.serverUrl = serverUrl;
    this.ws = null;
    this.token = null;
    this.publicKeyPem = null;
    this.publicKey = null; // CryptoKey
    this.username = null;
  }

  async connect() {
    return new Promise((resolve, reject) => {
      console.log(`🔗 Intentando conectar a ${this.serverUrl}...`);
      
      // Verificar que la URL comience con ws:// o wss://
      if (!this.serverUrl.startsWith('ws://') && !this.serverUrl.startsWith('wss://')) {
        reject(new Error('La URL debe comenzar con ws:// o wss://'));
        return;
      }

      try {
        this.ws = new WebSocket(this.serverUrl);

        let resolved = false;

        this.ws.onopen = () => {
          console.log("✅ Conectado al servidor");
          if (!resolved) {
            resolved = true;
            resolve();
          }
        };

        this.ws.onmessage = (event) => {
          try {
            console.log("📨 Mensaje recibido:", event.data);
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (e) {
            console.error("❌ Error al parsear mensaje:", e);
          }
        };

        this.ws.onerror = (error) => {
          console.error("❌ Error de WebSocket:", error);
          console.error("Estado del WebSocket:", this.ws.readyState);
          
          // Estados: 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
          const states = ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'];
          console.error(`Estado actual: ${states[this.ws.readyState] || 'UNKNOWN'}`);
          
          if (!resolved) {
            resolved = true;
            reject(new Error(`Error de conexión WebSocket. Verifica que el servidor esté corriendo en ${this.serverUrl}`));
          }
        };

        this.ws.onclose = (event) => {
          console.log("🔌 Desconectado del servidor");
          console.log(`Código: ${event.code}, Razón: ${event.reason || 'Sin razón'}`);
          
          // Códigos de error comunes
          const errorCodes = {
            1006: 'Conexión cerrada anormalmente. Posibles causas:\n' +
                   '  - El servidor no está corriendo\n' +
                   '  - Problemas con certificados SSL (si usas wss://)\n' +
                   '  - El puerto está bloqueado por el firewall\n' +
                   '  - La URL del servidor es incorrecta',
            1000: 'Conexión cerrada normalmente',
            1001: 'El servidor se está desconectando',
            1002: 'Error de protocolo',
            1003: 'Tipo de dato no soportado',
            1007: 'Datos inválidos',
            1008: 'Mensaje demasiado grande',
            1011: 'Error interno del servidor'
          };
          
          if (event.code !== 1000 && errorCodes[event.code]) {
            console.error(`💡 ${errorCodes[event.code]}`);
          }
          
          if (!resolved && event.code !== 1000) {
            resolved = true;
            reject(new Error(`Conexión cerrada con código ${event.code}: ${errorCodes[event.code] || 'Razón desconocida'}`));
          }
        };
      } catch (e) {
        console.error("❌ Error al crear WebSocket:", e);
        reject(e);
      }
    });
  }

  async login(username, password) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject("WebSocket no está conectado");
        return;
      }

      this.username = username;
      console.log(`🔐 Intentando login como ${username}...`);

      this.ws.send(
        JSON.stringify({
          action: "login",
          username: username,
          password: password,
        })
      );

      // Esperar respuesta (timeout de 5s)
      const timeout = setTimeout(() => {
        reject("Timeout en login");
      }, 5000);

      const originalOnMessage = this.ws.onmessage;
      this.ws.onmessage = async (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "login_success") {
          clearTimeout(timeout);
          this.token = data.token;
          this.publicKeyPem = data.public_key;
          try {
            await this.importPublicKeyFromPem(this.publicKeyPem);
            console.log("🔑 Public key imported into Web Crypto");
          } catch (e) {
            console.warn("⚠️ No se pudo importar la public key:", e);
          }
          this.ws.onmessage = originalOnMessage;
          resolve(data);
        } else if (data.type === "login_failed") {
          clearTimeout(timeout);
          this.ws.onmessage = originalOnMessage;
          reject(data.message);
        }
        // call original handler so UI can also react
        if (originalOnMessage)
          try {
            originalOnMessage(event);
          } catch (e) {}
      };
    });
  }

  handleMessage(data) {
    const { type, message, username, token, public_key } = data;

    switch (type) {
      case "login_success":
        console.log(`✅ Login exitoso: ${message}`);
        break;

      case "login_failed":
        console.error(`❌ Login fallido: ${message}`);
        break;

      case "message":
        console.log(`💬 [${username}] ${message}`);
        break;

      case "user_joined":
        console.log(`👤 ${username} se unió al chat`);
        console.log(`👥 Usuarios: ${data.users_online.join(", ")}`);
        break;

      case "user_left":
        console.log(`👋 ${username} se desconectó`);
        console.log(`👥 Usuarios: ${data.users_online.join(", ")}`);
        break;

      case "users_list":
        console.log(`👥 Online: ${data.users.join(", ")} (${data.count})`);
        break;

      case "error":
        console.error(`❌ Error: ${message}`);
        break;
    }
  }

  // Convert PEM (SPKI) public key to ArrayBuffer
  pemToArrayBuffer(pem) {
    // remove header/footer and newlines
    const b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\n/g, "")
      .trim();
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async importPublicKeyFromPem(pem) {
    const spki = this.pemToArrayBuffer(pem);
    // RSA-OAEP with SHA-256
    this.publicKey = await window.crypto.subtle.importKey(
      "spki",
      spki,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false,
      ["encrypt"]
    );
  }

  // Calculate SHA-256 hash and return as ArrayBuffer
  async calculateSHA256(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
    return hashBuffer;
  }

  // Encrypt plaintext with imported publicKey, including SHA-256 hash prefix
  // Format: [32 bytes hash] + [message bytes]
  async encryptWithPublicKey(plaintext) {
    if (!this.publicKey) throw new Error("Public key not imported");
    
    // Calculate SHA-256 hash (32 bytes)
    const msgHash = await this.calculateSHA256(plaintext);
    
    // Encode message as bytes
    const enc = new TextEncoder();
    const msgBytes = enc.encode(plaintext);
    
    // Combine hash (32 bytes) + message bytes
    const hashArray = new Uint8Array(msgHash);
    const combinedLength = hashArray.length + msgBytes.length;
    const combined = new Uint8Array(combinedLength);
    combined.set(hashArray, 0); // First 32 bytes: hash
    combined.set(msgBytes, hashArray.length); // Remaining bytes: message
    
    // Encrypt the combined data (hash + message) with RSA-OAEP
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      this.publicKey,
      combined
    );
    
    // Convert ArrayBuffer to base64
    const bytes = new Uint8Array(encrypted);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++)
      binary += String.fromCharCode(bytes[i]);
    
    const base64Encrypted = btoa(binary);
    
    // Log for debugging (similar to Python client)
    const hashHex = Array.from(hashArray)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    console.log(`🔒 Hash SHA-256: ${hashHex}`);
    console.log(`🔐 Mensaje cifrado (base64): ${base64Encrypted.substring(0, 50)}...`);
    
    return base64Encrypted;
  }

  async sendMessage(plaintext) {
    if (!this.token || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error("❌ No autenticado o desconectado");
      return;
    }

    console.log(`📤 Enviando mensaje...`);
    console.log(`💬 Mensaje original: ${plaintext}`);

    // If we have a publicKey, encrypt; otherwise send plaintext (testing)
    let payloadMessage = plaintext;
    let encryptedFlag = false;
    if (this.publicKey) {
      try {
        payloadMessage = await this.encryptWithPublicKey(plaintext);
        encryptedFlag = true;
        console.log(`✅ Mensaje cifrado con RSA-OAEP`);
      } catch (e) {
        console.warn(
          "⚠️ Error cifrando con public key, enviando sin cifrar:",
          e
        );
        payloadMessage = plaintext;
        encryptedFlag = false;
      }
    } else {
      console.warn("⚠️ No hay clave pública disponible, enviando mensaje sin cifrar");
    }

    this.ws.send(
      JSON.stringify({
        action: "send_message",
        token: this.token,
        message: payloadMessage,
        encrypted: encryptedFlag,
      })
    );
  }

  getUsers() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error("❌ WebSocket desconectado");
      return;
    }
    this.ws.send(JSON.stringify({ action: "get_users" }));
  }

  logout() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action: "logout" }));
    }
  }
}

// Ejemplo de uso (ejecutar en consola del navegador)
(async () => {
  const client = new ChatClient("wss://localhost:12345");
  try {
    await client.connect();
    await client.login("admin", "admin123");
    client.getUsers();
    // Enviar un mensaje de prueba
    setTimeout(() => client.sendMessage("¡Hola desde el front!"), 1000);
  } catch (error) {
    console.error("Error:", error);
  }
})();
