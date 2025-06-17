from flask import Flask, render_template, request, send_file
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode

print("App is starting...")


# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = './static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Function to derive key and IV
def derive_key_iv(password, salt):
    key_iv = scrypt(password.encode(), salt, key_len=64, N=2**14, r=8, p=1)
    key = key_iv[:32]
    iv = key_iv[32:48]
    return key, iv

# Padding function for AES
def pad(data):
    padding_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_length]) * padding_length

# Unpadding function for AES
def unpad(data):
    padding_length = data[-1]
    if padding_length > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-padding_length]

# Encryption function
def encrypt_image(image_path, password):
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()

        salt = get_random_bytes(16)
        key, iv = derive_key_iv(password, salt)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(image_data)
        encrypted_data = cipher.encrypt(padded_data)

        encrypted_file_path = image_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        # Generate QR code with salt, iv, and key
        qr_data = f"Salt={salt.hex()} IV={iv.hex()} Key={key.hex()}"
        qr_code_path = image_path + "_key_qr.png"
        qr = qrcode.make(qr_data)
        qr.save(qr_code_path)

        return encrypted_file_path, qr_code_path
    except Exception as e:
        return None, f"Error encrypting image: {e}"

# Decryption function
def decrypt_image(qr_code_path, password):
    try:
        qr = Image.open(qr_code_path)
        qr_data = decode(qr)

        if not qr_data:
            return None, "No QR code found."

        qr_data = qr_data[0].data.decode('utf-8')
        parts = qr_data.split(' ')
        salt = bytes.fromhex(parts[0].split('=')[1])
        iv = bytes.fromhex(parts[1].split('=')[1])
        key = bytes.fromhex(parts[2].split('=')[1])

        # Read encrypted file
        encrypted_file_path = qr_code_path.replace('_key_qr.png', '.enc')
        if not os.path.exists(encrypted_file_path):
            return None, "Encrypted file not found."

        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()[32:]  # Skip salt and IV

        # Derive key from password
        derived_key, _ = derive_key_iv(password, salt)
        if derived_key != key:
            return None, "Incorrect password."

        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_data)

        decrypted_file_path = encrypted_file_path.replace('.enc', '_decrypted.png')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        return decrypted_file_path, None
    except Exception as e:
        return None, f"Error decrypting image: {e}"

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password', '').strip()

        if not file or file.filename == '':
            return "No file selected."
        if not password:
            return "Password is required."

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        encrypted_path, qr_path = encrypt_image(file_path, password)
        if encrypted_path:
            return render_template('result.html', encrypted_file=encrypted_path, qr_code=qr_path)
        else:
            return "Error encrypting file."
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password', '').strip()

        if not file or file.filename == '':
            return "No file selected."
        if not password:
            return "Password is required."

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        decrypted_path, error = decrypt_image(file_path, password)
        if decrypted_path:
            return send_file(decrypted_path, as_attachment=True)
        else:
            return f"Error decrypting file: {error}"
    return render_template('decrypt.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
