CNS Secure Vault

A web app that stores files securely using AES-256-GCM encryption and RSA digital signatures. It demonstrates confidentiality, integrity and authenticity, and lets you simulate attacks to see tampering get detected.

Built as a Cryptography and Network Security (CNS) project.

---------Features---------


Encrypt and sign on upload: each file is encrypted with AES-256-GCM, then the encrypted bytes are signed with RSA-PSS (SHA-256).

View encrypted content: hex dump, base64, nonce and SHA-256 hashes of the stored file, so you can see it is unreadable without the key.

Verify before decrypting: the RSA signature and the AES-GCM authentication tag are checked separately. Content is only decrypted and previewed if both pass.

Preview decrypted files: text, PDF and image files can be viewed in the browser after verification.

Simulate attacks: flip a bit in the ciphertext, truncate the file, or swap the signature, then watch the status change to TAMPERED.

Restore and delete: reset a file after an attack, or remove it from the vault.

How it works

Upload  ->  AES-256-GCM encrypt  ->  SHA-256 + RSA-PSS sign  ->  Store ,Download  ->  Verify signature  ->  Check GCM tag  ->  Decrypt

Step	Algorithm	Purpose
Encryption	AES-256-GCM (random 12-byte nonce)	Confidentiality and integrity of the ciphertext

Signing	RSA-2048 with PSS padding, SHA-256	Authenticity and tamper detection

Storage format	nonce || ciphertext || tag	Everything needed to decrypt, in one file

Tech stack

Python 3 and Flask

cryptography library

SQLite for file metadata

HTML, CSS and JavaScript frontend

Getting started

Requires Python 3.9 or newer.

bash
git clone https://github.com/Aayushcommits/cns-secure-vault.git
cd cns-secure-vault

pip install -r requirements.txt

python app.py

Open http://127.0.0.1:5000 in your browser.

AES and RSA keys are generated automatically on the first run and saved in keys/.

