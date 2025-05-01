from flask import Flask, render_template, request, jsonify, session
import secrets
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)

# Create templates directory if it doesn't exist
os.makedirs('templates', exist_ok=True)

# Create static directory if it doesn't exist
os.makedirs('static', exist_ok=True)

# Write HTML template
with open('templates/index.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSA Encryption Tool</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="container">
        <h1>RSA Encryption/Decryption Tool</h1>

        <div class="card">
            <h2>Key Generation</h2>
            <form id="keyGenForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label for="keySize">Key Size (bits):</label>
                    <select id="keySize" name="keySize" class="form-control">
                        <option value="1024">1024 - Faster but less secure</option>
                        <option value="2048" selected>2048 - Recommended</option>
                        <option value="4096">4096 - More secure but slower</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Generate Keys</button>
            </form>
            <div class="loader" id="keyGenLoader" style="display: none;"></div>
        </div>

        <div class="card" id="keysCard" style="display: none;">
            <h2>Your Keys</h2>
            <div class="key-container">
                <h3>Public Key</h3>
                <div class="key-display">
                    <textarea id="publicKey" readonly></textarea>
                    <button class="btn btn-sm" onclick="copyToClipboard('publicKey')">Copy</button>
                </div>

                <h3>Private Key</h3>
                <div class="key-display">
                    <textarea id="privateKey" readonly></textarea>
                    <button class="btn btn-sm" onclick="copyToClipboard('privateKey')">Copy</button>
                </div>
                <div class="alert alert-warning">
                    <strong>Warning:</strong> Keep your private key secure! Never share it with others.
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Encryption</h2>
            <form id="encryptForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label for="encryptMessage">Message to Encrypt:</label>
                    <textarea id="encryptMessage" name="message" class="form-control" rows="3" required></textarea>
                </div>
                <div class="form-group">
                    <label for="encryptKey">Public Key:</label>
                    <textarea id="encryptKey" name="key" class="form-control" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn btn-success">Encrypt</button>
            </form>
            <div class="loader" id="encryptLoader" style="display: none;"></div>
            <div id="encryptedResult" style="display: none;">
                <h3>Encrypted Message</h3>
                <div class="key-display">
                    <textarea id="encryptedMessage" readonly></textarea>
                    <button class="btn btn-sm" onclick="copyToClipboard('encryptedMessage')">Copy</button>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Decryption</h2>
            <form id="decryptForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="form-group">
                    <label for="decryptMessage">Encrypted Message (Base64):</label>
                    <textarea id="decryptMessage" name="message" class="form-control" rows="3" required></textarea>
                </div>
                <div class="form-group">
                    <label for="decryptKey">Private Key:</label>
                    <textarea id="decryptKey" name="key" class="form-control" rows="5" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Decrypt</button>
            </form>
            <div class="loader" id="decryptLoader" style="display: none;"></div>
            <div id="decryptedResult" style="display: none;">
                <h3>Decrypted Message</h3>
                <div class="key-display">
                    <textarea id="decryptedMessage" readonly></textarea>
                    <button class="btn btn-sm" onclick="copyToClipboard('decryptedMessage')">Copy</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            element.select();
            document.execCommand('copy');

            // Show copy feedback
            const originalText = element.nextElementSibling.textContent;
            element.nextElementSibling.textContent = 'Copied!';
            setTimeout(() => {
                element.nextElementSibling.textContent = originalText;
            }, 1500);
        }

        document.getElementById('keyGenForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const keySize = document.getElementById('keySize').value;
            const loader = document.getElementById('keyGenLoader');

            loader.style.display = 'block';

            fetch('/generate-keys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf_token]').value
                },
                body: JSON.stringify({ keySize: keySize })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('publicKey').value = data.publicKey;
                document.getElementById('privateKey').value = data.privateKey;
                document.getElementById('keysCard').style.display = 'block';
                loader.style.display = 'none';
            })
            .catch(error => {
                console.error('Error:', error);
                loader.style.display = 'none';
                alert('Error generating keys. Please try again.');
            });
        });

        document.getElementById('encryptForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const message = document.getElementById('encryptMessage').value;
            const key = document.getElementById('encryptKey').value;
            const loader = document.getElementById('encryptLoader');

            loader.style.display = 'block';

            fetch('/encrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf_token]').value
                },
                body: JSON.stringify({ message: message, key: key })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                } else {
                    document.getElementById('encryptedMessage').value = data.encryptedMessage;
                    document.getElementById('encryptedResult').style.display = 'block';
                }
                loader.style.display = 'none';
            })
            .catch(error => {
                console.error('Error:', error);
                loader.style.display = 'none';
                alert('Error encrypting message. Please try again.');
            });
        });

        document.getElementById('decryptForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const message = document.getElementById('decryptMessage').value;
            const key = document.getElementById('decryptKey').value;
            const loader = document.getElementById('decryptLoader');

            loader.style.display = 'block';

            fetch('/decrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf_token]').value
                },
                body: JSON.stringify({ message: message, key: key })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(data.error);
                } else {
                    document.getElementById('decryptedMessage').value = data.decryptedMessage;
                    document.getElementById('decryptedResult').style.display = 'block';
                }
                loader.style.display = 'none';
            })
            .catch(error => {
                console.error('Error:', error);
                loader.style.display = 'none';
                alert('Error decrypting message. Please try again.');
            });
        });
    </script>
</body>
</html>
''')

# Write CSS styles
with open('static/style.css', 'w') as f:
    f.write('''
:root {
    --primary-color: #4a6fa5;
    --secondary-color: #6c757d;
    --success-color: #28a745;
    --danger-color: #dc3545;
    --warning-color: #ffc107;
    --light-color: #f8f9fa;
    --dark-color: #343a40;
    --border-radius: 8px;
    --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f7fc;
    padding: 20px;
}

.container {
    max-width: 1000px;
    margin: 0 auto;
    padding: 20px;
}

h1 {
    text-align: center;
    margin-bottom: 30px;
    color: var(--primary-color);
}

h2 {
    color: var(--primary-color);
    margin-bottom: 20px;
    font-size: 1.5rem;
}

h3 {
    color: var(--secondary-color);
    margin: 15px 0 10px;
    font-size: 1.2rem;
}

.card {
    background-color: white;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
    padding: 25px;
    margin-bottom: 30px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
}

.form-control {
    width: 100%;
    padding: 10px 15px;
    border: 1px solid #ddd;
    border-radius: var(--border-radius);
    font-size: 16px;
    transition: border-color 0.3s;
}

.form-control:focus {
    border-color: var(--primary-color);
    outline: none;
}

textarea.form-control {
    resize: vertical;
    min-height: 100px;
}

.btn {
    display: inline-block;
    font-weight: 500;
    text-align: center;
    white-space: nowrap;
    vertical-align: middle;
    user-select: none;
    border: 1px solid transparent;
    padding: 10px 15px;
    font-size: 16px;
    border-radius: var(--border-radius);
    transition: all 0.3s;
    cursor: pointer;
}

.btn-sm {
    padding: 5px 10px;
    font-size: 14px;
}

.btn-primary {
    color: white;
    background-color: var(--primary-color);
    border-color: var(--primary-color);
}

.btn-primary:hover {
    background-color: #3a5a8c;
    border-color: #3a5a8c;
}

.btn-success {
    color: white;
    background-color: var(--success-color);
    border-color: var(--success-color);
}

.btn-success:hover {
    background-color: #218838;
    border-color: #1e7e34;
}

.key-container {
    background-color: #f8f9fa;
    border-radius: var(--border-radius);
    padding: 15px;
}

.key-display {
    position: relative;
    margin-bottom: 15px;
}

.key-display textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: var(--border-radius);
    font-family: monospace;
    font-size: 14px;
    resize: vertical;
    min-height: 100px;
    background-color: #f8f9fa;
}

.key-display button {
    position: absolute;
    top: 5px;
    right: 5px;
    background-color: white;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    cursor: pointer;
}

.alert {
    padding: 12px;
    border-radius: var(--border-radius);
    margin: 15px 0;
    font-size: 14px;
}

.alert-warning {
    background-color: #fff3cd;
    border: 1px solid #ffeeba;
    color: #856404;
}

.loader {
    border: 4px solid #f3f3f3;
    border-top: 4px solid var(--primary-color);
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin: 15px auto;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

@media (max-width: 768px) {
    .container {
        padding: 10px;
    }

    .card {
        padding: 15px;
    }
}
''')


# Route for home page
@app.route('/')
def home():
    return render_template('index.html')


# Route for key generation
@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    data = request.json
    key_size = int(data.get('keySize', 2048))

    # Validate key size
    if key_size not in [1024, 2048, 4096]:
        return jsonify({'error': 'Invalid key size'}), 400

    try:
        # Generate RSA Key Pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Store keys in session
        session['private_key'] = private_pem
        session['public_key'] = public_pem

        return jsonify({
            'publicKey': public_pem,
            'privateKey': private_pem
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Route for encryption
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message', '')
    key_str = data.get('key', '')

    if not message or not key_str:
        return jsonify({'error': 'Message and key are required'}), 400

    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            key_str.encode(),
            backend=default_backend()
        )

        # Encrypt message
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Return base64 encoded ciphertext
        return jsonify({
            'encryptedMessage': base64.b64encode(ciphertext).decode()
        })
    except Exception as e:
        return jsonify({'error': f'Encryption error: {str(e)}'}), 500


# Route for decryption
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message = data.get('message', '')
    key_str = data.get('key', '')

    if not encrypted_message or not key_str:
        return jsonify({'error': 'Encrypted message and key are required'}), 400

    try:
        # Load private key
        private_key = serialization.load_pem_private_key(
            key_str.encode(),
            password=None,
            backend=default_backend()
        )

        # Decode base64 encrypted message
        try:
            ciphertext = base64.b64decode(encrypted_message)
        except Exception:
            return jsonify({'error': 'Invalid encrypted message format'}), 400

        # Decrypt message
        decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({
            'decryptedMessage': decrypted_message.decode()
        })
    except Exception as e:
        return jsonify({'error': f'Decryption error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)