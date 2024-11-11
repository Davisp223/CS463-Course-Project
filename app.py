from flask import Flask, render_template, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

app = Flask(__name__)

# Route for index, renders the index.html file from the 'templates' folder
@app.route('/')
def index():
    return render_template('index.html')  # Flask looks for 'index.html' in the templates/ folder

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem

# Generate Shared Key from Password
def generate_shared_key(password):
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt Text using Public Key
def encrypt_with_public_key(public_key, plaintext):
    encrypted = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

# Decrypt Text using Private Key
def decrypt_with_private_key(private_key, ciphertext):
    encrypted_data = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Generate Digital Signature
def generate_signature(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Verify Digital Signature
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Signature is valid"
    except Exception as e:
        return f"Signature is invalid: {str(e)}"

@app.route("/generate-keys", methods=["GET"])
def generate_keys():
    private_pem, public_pem = generate_rsa_keys()
    return jsonify({
        "public_key": public_pem.decode(),
        "private_key": private_pem.decode()
    })

@app.route("/encrypt", methods=["POST"])
def encrypt():
    public_key_pem = request.json.get("public_key")
    plaintext = request.json.get("plaintext")

    if public_key_pem is None:
        return jsonify({"error": "Public key is required"}), 400

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    except ValueError as e:
        return jsonify({"error": f"Invalid public key: {str(e)}"}), 400

    encrypted_text = encrypt_with_public_key(public_key, plaintext)
    return jsonify({"encrypted": encrypted_text})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    private_key_pem = request.json.get("private_key")
    ciphertext = request.json.get("ciphertext")
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    decrypted_text = decrypt_with_private_key(private_key, ciphertext)
    return jsonify({"decrypted": decrypted_text})

@app.route("/sign", methods=["POST"])
def sign():
    private_key_pem = request.json.get("private_key")
    message = request.json.get("message")
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    signature = generate_signature(private_key, message)
    return jsonify({"signature": signature})

@app.route("/verify", methods=["POST"])
def verify():
    public_key_pem = request.json.get("public_key")
    message = request.json.get("message")
    signature = request.json.get("signature")
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    verification_result = verify_signature(public_key, message, signature)
    return jsonify({"verification_result": verification_result})

if __name__ == "__main__":
    app.run(debug=True)
