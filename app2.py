import random
import math
from flask import Flask, request, jsonify, render_template
import requests
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__, template_folder="templates")
messages = []

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

# --- Funções RSA Aprimoradas ---
def is_prime(num):
    """Verificação robusta de primalidade."""
    if num < 2:
        return False
    for i in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if num % i == 0:
            return num == i
    d = num - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        if a >= num:
            continue
        x = pow(a, d, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def generate_prime(min_value, max_value):
    """Gera primos grandes com Miller-Rabin."""
    while True:
        p = random.randint(min_value, max_value)
        if is_prime(p):
            return p

def generate_rsa_keys():
    """Geração de chaves com verificação."""
    p = generate_prime(100000, 500000)
    q = generate_prime(100000, 500000)
    n = p * q
    phi = (p-1)*(q-1)
    
    e = 65537  # Padrão RSA
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return generate_rsa_keys()  # Recursão se inválido
    
    # Verificação final
    if (e * d) % phi != 1:
        return generate_rsa_keys()
    
    return (e, n), (d, n)

def encrypt_rsa(message, e, n):
    encrypted = []
    for char in message:
        char_code = ord(char)
        encrypted_num = pow(char_code, e, n)
        print(f"Char: {char} (ASCII: {char_code}) → Criptografado: {encrypted_num}")
        encrypted.append(encrypted_num)
    return encrypted

def decrypt_rsa(encrypted, d, n):
    decrypted = []
    for num in encrypted:
        decrypted_num = pow(num, d, n)
        print(f"Valor criptografado: {num} → Descriptografado: {decrypted_num} (ASCII: {chr(decrypted_num)})")
        decrypted.append(chr(decrypted_num))
    return ''.join(decrypted)

def fetch_public_key(url):
    try:
        response = requests.get(url)
        data = response.json()
        return (data["e"], data["n"])
    except Exception as e:
        print(f"Erro ao buscar chave pública: {e}")
        return None

# --- Novas funções para autenticação ---
def sign_message(message, private_key):
    """Assina uma mensagem com a chave privada RSA."""
    d, n = private_key
    signature = pow(int.from_bytes(message.encode(), 'big'), d, n)
    return signature

def verify_signature(signature, message, public_key):
    """Verifica uma assinatura com a chave pública RSA."""
    e, n = public_key
    decrypted_signature = pow(signature, e, n)
    original_message = int.from_bytes(message.encode(), 'big')
    return decrypted_signature == original_message

# --- Configuração ---
bob_public_key, bob_private_key = generate_rsa_keys()
print(f"CHAVE PÚBLICA DO BOB (e, n): {bob_public_key}")

alice_public_key = None
partner_webhook_url = None  # URL de callback da Alice (ex: "http://localhost:5000/webhook_callback")

print(f"Chave pública da Alice obtida: {alice_public_key}")

@app.route("/", methods=["GET"])
def index():
    return render_template("chat2.html", messages=messages)

@app.route("/public_key", methods=["GET"])
def public_key():
    return jsonify({"e": bob_public_key[0], "n": bob_public_key[1]})

@app.route("/register_webhook", methods=["POST"])
def register_webhook():
    global partner_webhook_url
    data = request.json
    partner_webhook_url = data.get("webhook_url")  # Ex: "http://localhost:5001/webhook_callback"
    
    if not partner_webhook_url:
        return jsonify({"error": "URL do webhook inválida"}), 400
    
    if not is_valid_url(partner_webhook_url):
        return jsonify({"error": "URL inválida"}), 400
    
    return jsonify({"status": "Webhook registrado com sucesso!"})

@app.route("/webhook_callback", methods=["POST"])
def webhook_callback():
    if not request.json or "signature" not in request.json:
        return jsonify({"error": "Assinatura ausente"}), 400
    
    # Verifica a assinatura (exemplo para Alice em app1.py):
    if not verify_signature(
        request.json["signature"],
        "new_message",
        alice_public_key  # Usa a chave pública do parceiro (Alice)
    ):
        return jsonify({"error": "Assinatura inválida"}), 401
    
    print("Notificação de webhook autenticada!")
    return jsonify({"status": "ok"})

@app.route("/handshake", methods=["POST"])
def handshake():
    global alice_public_key, partner_webhook_url
    data = request.json
    nonce = data["nonce"]
    signature = data["signature"]
    partner_public_key = fetch_public_key(data["partner_key_url"])

    if not verify_signature(signature, nonce, partner_public_key):
        return jsonify({"error": "Autenticação falhou!"}), 401

    if "alice" in data["partner_key_url"]:  # Se o parceiro é Alice
        alice_public_key = partner_public_key

    if "webhook_url" in data:  # Se o parceiro enviou sua URL de webhook
        partner_webhook_url = data["webhook_url"]
        print(f"Webhook do parceiro registrado: {partner_webhook_url}")

    return jsonify({"status": "Autenticado com sucesso!"})

# Endpoint para iniciar handshake
@app.route("/init_handshake", methods=["POST"])
def init_handshake():
    nonce = str(random.randint(1000, 9999))  # Nonce aleatório
    signature = sign_message(nonce, bob_private_key)  # ou bob_private_key
    response = requests.post(
        "http://localhost:5001/handshake",  # ou 5000 para Bob
        json={
            "nonce": nonce,
            "signature": signature,
            "partner_key_url": "http://localhost:5000/public_key",  # ou 5001
            "webhook_url": "http://localhost:5000/webhook_callback"  # Adicione esta linha
        }
    )
    return jsonify({"status": "Handshake iniciado!"})

@app.route("/send", methods=["POST"])
def send():
    global alice_public_key
    
    # 1. Verifica se já tem a chave de Alice
    if alice_public_key is None:
        # 2. Executa handshake automático
        try:
            # Gera nonce aleatório
            nonce = str(random.randint(1000, 9999))
            
            # Faz handshake com Alice
            response = requests.post(
                "http://localhost:5000/handshake",
                json={
                    "nonce": nonce,
                    "signature": sign_message(nonce, bob_private_key),
                    "partner_key_url": "http://localhost:5001/public_key"
                },
                timeout=5
            )
            
            if not response.ok:
                return jsonify({"error": "Handshake falhou"}), 500
                
            # Obtém chave pública de Alice
            alice_public_key = fetch_public_key("http://localhost:5000/public_key")
            if not alice_public_key:
                return jsonify({"error": "Falha ao obter chave de Alice"}), 500
                
        except Exception as e:
            print(f"Erro no handshake: {str(e)}")
            return jsonify({"error": "Erro na comunicação"}), 500

    # 3. Envia a mensagem
    text = request.form.get("text", "").strip()
    if not text:
        return jsonify({"error": "Mensagem vazia"}), 400

    try:
        encrypted_msg = encrypt_rsa(text, *alice_public_key)
        response = requests.post(
            "http://localhost:5000/receive",
            json={"text": encrypted_msg},
            timeout=5
        )
        response.raise_for_status()
        return jsonify({"status": "ok"})
        
    except Exception as e:
        print(f"Erro ao enviar mensagem: {str(e)}")
        return jsonify({"error": "Falha ao enviar mensagem"}), 500


@app.route("/receive", methods=["POST"])
def receive():
    # 1. Validação básica da requisição
    if not request.json or "text" not in request.json:
        print("[ERRO] Dados inválidos recebidos")
        return jsonify({"error": "Dados inválidos"}), 400

    encrypted_msg = request.json["text"]
    print(f"\n[BOB] Mensagem criptografada recebida: {encrypted_msg}")
    
    # 2. Descriptografa a mensagem (Bob usa sua PRIVADA)
    try:
        decrypted_msg = decrypt_rsa(encrypted_msg, bob_private_key[0], bob_private_key[1])
        print(f"[BOB] Mensagem descriptografada: {decrypted_msg}")
    except Exception as e:
        print(f"[BOB] ERRO ao descriptografar: {str(e)}")
        return jsonify({"error": "Mensagem inválida"}), 400

    # 3. Armazena a mensagem (identificando o remetente como Alice)
    messages.append({
        "sender": "Alice",
        "text": decrypted_msg,
        "timestamp": datetime.now().isoformat()
    })

    # 4. Notifica Alice via webhook (se registrado)
    if partner_webhook_url:
        print(f"[BOB] Notificando Alice via webhook: {partner_webhook_url}")
        try:
            # Assina a notificação para segurança
            signature = sign_message("new_message", bob_private_key)
            
            response = requests.post(
                partner_webhook_url,
                json={
                    "event": "new_message",
                    "sender": "Bob",
                    "signature": signature,
                    "timestamp": datetime.now().isoformat()
                },
                timeout=3
            )
            
            if response.status_code != 200:
                print(f"[BOB] Webhook retornou erro: {response.status_code}")
        except Exception as e:
            print(f"[BOB] ERRO no webhook: {str(e)}")

    return jsonify({
        "status": "ok",
        "message": "Mensagem recebida e webhook notificado"
    })

@app.route("/messages", methods=["GET"])
def get_messages():
    return jsonify(messages)

if __name__ == "__main__":
    app.run(port=5001, debug=True)  # Bob roda na 5001