# Secure-File-Storage-System-with-RBAC
A Flask-based secure file storage system with Role-Based Access Control (RBAC), AES-256 file encryption, RSA key exchange, user authentication, and HMAC-SHA256 audit logging. Designed for secure file management with proper access controls.

A secure web-based file storage system built using Flask, featuring:

🔑 AES-256 file encryption

🔐 RSA-2048 key exchange

🔒 Role-Based Access Control (RBAC)

🔏 HMAC-SHA256 audit logging

🔐 User authentication with bcrypt

Features:
User Authentication – Register and login with securely hashed passwords using bcrypt.

Role Management – Admin, User, and Guest roles with access restrictions.

File Encryption – Uploads are encrypted using AES-256 before storage.

RSA Key Exchange – Secure sharing of AES keys using RSA-2048.

Audit Logging – All file access and modification actions are logged and secured with HMAC-SHA256.

Access Control – Only authorized roles can access or modify specific files.

Frontend Interface – Simple and user-friendly UI for login, file upload, and download.


Tech Stack:
Backend: Python, Flask, SQLAlchemy

Encryption: PyCryptodome (AES, RSA), HMAC

Authentication: Flask-Login, Bcrypt

Frontend: HTML, CSS (Bootstrap optional)

Database: SQLite (can be replaced with PostgreSQL or MySQL)


Getting Started:

Clone the repo:
git clone https://github.com/your-username/secure-file-storage-rbac.git
cd secure-file-storage-rbac

Install dependencies:
pip install -r requirements.txt

Run the application:
flask --app main run


Security Overview
Security Layer	          Details
AES-256	            Encrypts files before saving
RSA-2048	          Encrypts the AES key
Bcrypt	            Hashes passwords securely
HMAC-SHA256	        Protects and validates audit logs
RBAC	              Ensures users only access what they’re allowed
