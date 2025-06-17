🔐 Secure Image Encryption & Decryption Web App

A secure and elegant web application built using Flask that allows users to encrypt images with a password and decrypt them later using a QR code containing the cryptographic key. Perfect for learning and demonstrating concepts like AES encryption, password-based key derivation, and secure image handling.

🚀 Features

- AES-256 encryption in CBC mode with padding
- Password-based key derivation using `scrypt`
- Random salt and IV generation for enhanced security
- QR code generation with encryption metadata (salt, IV, key)
- Secure image upload and storage
- Image decryption using QR code + password
- User-friendly, responsive UI with clean design

🛠 Tech Stack

- Backend: Flask (Python)
- Frontend: HTML, CSS
- Cryptography: PyCryptodome (`AES`, `scrypt`)
- Image & QR Handling: Pillow, qrcode, pyzbar

✅ Installation Instructions

Clone the Repository
git clone https://github.com/nikitahegde55/encrypt-decrypt.git
cd image-encrypt-decrypt

Install Python Dependencies
pip install -r requirements.txt

Install ZBar DLL (Required for QR Decoding)
📥 Download and install the Visual C++ 2013 Redistributable:
https://www.microsoft.com/en-us/download/details.aspx?id=40784

▶️ Run the App
python app.py
Then open your browser and go to:
📍 http://127.0.0.1:5000/

