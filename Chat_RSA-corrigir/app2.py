import random
import math
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__, template_folder="templates")
messages = []

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

# --- Configuração ---
bob_public_key, bob_private_key = generate_rsa_keys()
print(f"CHAVE PÚBLICA DO BOB (e, n): {bob_public_key}")

alice_public_key = alice_public_key = None

print(f"Chave pública da Alice obtida: {alice_public_key}")

@app.route("/", methods=["GET"])
def index():
    return render_template("chat1.html", messages=messages)

@app.route("/send", methods=["POST"])
def send():
    global alice_public_key
    if alice_public_key is None:
        alice_public_key = fetch_public_key("http://localhost:5000/public_key")
        if alice_public_key is None:
            return jsonify({"error": "Não foi possível obter a chave pública de Alice"}), 500

    text = request.form.get("text", "")
    print(f"\n[BOB ENVIA] Original: {text}")
    
    encrypted_msg = encrypt_rsa(text, *alice_public_key)
    print(f"[BOB ENVIA] Criptografada: {encrypted_msg}")
    
    requests.post("http://localhost:5000/receive", json={"text": encrypted_msg})
    return jsonify({"status": "ok"})


@app.route("/receive", methods=["POST"])
def receive():
    encrypted_msg = request.json["text"]
    print(f"\n[RECEBIMENTO] Mensagem criptografada recebida: {encrypted_msg}")
    
    decrypted_msg = decrypt_rsa(encrypted_msg, bob_private_key[0], bob_private_key[1])  # BOB usa sua chave privada
    print(f"[RECEBIMENTO] Mensagem descriptografada: {decrypted_msg}")
    
    messages.append({"sender": "Alice", "text": decrypted_msg})
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(port=5001, debug=True)  # Bob roda na 5001