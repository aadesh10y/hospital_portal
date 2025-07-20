"""
Secure Hospital Patient Portal
A Flask-based web application with digital certificate authentication
and document signing capabilities for healthcare environments.
"""

import os
import sqlite3
import hashlib
import secrets
import logging
import base64
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from functools import wraps

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

# Configuration
UPLOAD_FOLDER = 'uploads'
CERTS_FOLDER = 'certificates'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'hospital_portal.db')
SECRET_KEY = secrets.token_hex(32)
DEFAULT_PORT = 5000
MAX_PORT_ATTEMPTS = 10

# Ensure directories exist
for folder in [UPLOAD_FOLDER, CERTS_FOLDER]:
    Path(folder).mkdir(exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hospital_portal.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def is_port_available(port: int) -> bool:
    """Check if a port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False

def find_available_port(start_port: int, max_attempts: int) -> int:
    """Find an available port starting from start_port"""
    port = start_port
    for _ in range(max_attempts):
        if is_port_available(port):
            return port
        logger.warning(f"Port {port} is in use, trying {port + 1}")
        port += 1
    raise RuntimeError(f"No available ports found between {start_port} and {start_port + max_attempts - 1}")

def require_admin(f):
    """Decorator to restrict access to admin users"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'Admin':
            flash('Access denied: Admin privileges required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

class CertificateAuthority:
    """Hospital Certificate Authority for managing certificates"""
    
    def __init__(self):
        self.ca_private_key = None
        self.ca_certificate = None
        self._initialize_ca()
    
    def _initialize_ca(self):
        """Initialize or load the CA certificate and private key"""
        ca_key_path = Path(CERTS_FOLDER) / 'ca_private_key.pem'
        ca_cert_path = Path(CERTS_FOLDER) / 'ca_certificate.pem'
        
        if ca_key_path.exists() and ca_cert_path.exists():
            try:
                with open(ca_key_path, 'rb') as f:
                    self.ca_private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=b'hospital_ca_password',
                        backend=default_backend()
                    )
                with open(ca_cert_path, 'rb') as f:
                    self.ca_certificate = x509.load_pem_x509_certificate(
                        f.read(),
                        backend=default_backend()
                    )
                logger.info("CA certificate and key loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load CA key or certificate: {str(e)}. Regenerating CA.")
                self._generate_ca()
        else:
            logger.info("CA key or certificate not found. Generating new CA.")
            self._generate_ca()
    
    def _generate_ca(self):
        """Generate a new CA certificate and private key"""
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hospital Security CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Hospital CA"),
        ])
        
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
        
        ca_key_path = Path(CERTS_FOLDER) / 'ca_private_key.pem'
        ca_cert_path = Path(CERTS_FOLDER) / 'ca_certificate.pem'
        
        with open(ca_key_path, 'wb') as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'hospital_ca_password')
            ))
        
        with open(ca_cert_path, 'wb') as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        
        logger.info("New CA certificate and key generated")
    
    def issue_certificate(self, user_id: str, public_key, user_role: str) -> bytes:
        """Issue a certificate for a user"""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hospital"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"Hospital {user_role}"),
            x509.NameAttribute(NameOID.COMMON_NAME, user_id),
        ])
        
        try:
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.ca_certificate.subject
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(f"{user_id}@hospital.local")]),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
            
            logger.info(f"Certificate issued for user: {user_id}")
            return certificate.public_bytes(serialization.Encoding.PEM)
        except Exception as e:
            logger.error(f"Failed to issue certificate for {user_id}: {str(e)}")
            raise
    
    def verify_certificate(self, cert_data: bytes) -> bool:
        try:
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            current_time = datetime.now(timezone.utc).astimezone(timezone.utc)
            logger.debug(f"Current time: {current_time}, Type: {type(current_time)}, TZ: {current_time.tzinfo}")
            logger.debug(f"Cert not_valid_after: {certificate.not_valid_after}, Type: {type(certificate.not_valid_after)}, TZ: {certificate.not_valid_after.tzinfo}")
            # Normalize both datetimes to UTC for comparison
            if certificate.not_valid_after.astimezone(timezone.utc) < current_time:
                logger.warning(f"Certificate expired: {certificate.not_valid_after}")
                return False
            if certificate.not_valid_before.astimezone(timezone.utc) > current_time:
                logger.warning(f"Certificate not yet valid: {certificate.not_valid_before}")
                return False
            self.ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            logger.info("Certificate verification successful")
            return True
        except ValueError as e:
            logger.error(f"Certificate verification failed due to invalid signature or format: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Certificate verification failed: {str(e)}")
            return False

class DocumentSigner:
    """Handle document signing and verification"""
    
    @staticmethod
    def sign_document(document_content: bytes, private_key) -> str:
        """Sign a document with a private key"""
        document_hash = hashlib.sha256(document_content).digest()
        signature = private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(document_content: bytes, signature_b64: str, certificate_data: bytes) -> bool:
        """Verify a document signature"""
        try:
            certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
            public_key = certificate.public_key()
            signature = base64.b64decode(signature_b64)
            document_hash = hashlib.sha256(document_content).digest()
            public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("Document signature verification successful")
            return True
        except Exception as e:
            logger.error(f"Document signature verification failed: {str(e)}")
            return False

class DatabaseManager:
    """Handle database operations"""
    
    @staticmethod
    def init_db():
        """Initialize the database"""
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                certificate_path TEXT,
                private_key_path TEXT,
                keys_downloaded INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                signature TEXT,
                signer_certificate TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    @staticmethod
    def log_action(user_id: Optional[int], action: str, details: str, ip_address: str):
        """Log an action to the audit log"""
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            (user_id, action, details, ip_address)
        )
        conn.commit()
        conn.close()

# Initialize components
ca = CertificateAuthority()
DatabaseManager.init_db()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    # Restrict self-registration to non-Admin roles
    if role == 'Admin':
        return jsonify({'success': False, 'message': 'Admin role cannot be assigned during self-registration. Contact an administrator.'})
    
    # Define allowed roles for self-registration, ensuring Patient and Nurse are included
    allowed_roles = ['Doctor', 'User', 'Patient', 'Nurse']
    if role not in allowed_roles:
        return jsonify({'success': False, 'message': 'Invalid role selected.'})
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Username or email already exists'})
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        certificate_pem = ca.issue_certificate(username, public_key, role)
        
        private_key_path = Path(CERTS_FOLDER) / f'{username}_secret_key.pem'
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        logger.info(f"Secret key generated and saved at {private_key_path}")
        
        certificate_path = Path(CERTS_FOLDER) / f'{username}_public_id.pem'
        with open(certificate_path, 'wb') as f:
            f.write(certificate_pem)
        logger.info(f"Public ID generated and saved at {certificate_path}")
        
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, role, certificate_path, private_key_path, keys_downloaded) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (username, email, password_hash, role, str(certificate_path), str(private_key_path), 0)
        )
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(None, 'USER_REGISTERED', f'User {username} registered with role {role}', request.remote_addr)
        return jsonify({'success': True, 'message': f'Registration successful for {username}! Please login to download your public ID and secret key.'})
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Existing POST logic (your login validation, etc.)

    username = request.form['username']
    password = request.form['password']
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, role, certificate_path, private_key_path, keys_downloaded FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user[1], password):
            return jsonify({'success': False, 'message': 'Invalid username or password'})
        
        if user[5] == 0:  # keys_downloaded == 0
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2]
            DatabaseManager.log_action(user[0], 'LOGIN_SUCCESS', 'Initial login without keys', request.remote_addr)
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        
        certificate_file = request.files.get('certificate')
        private_key_file = request.files.get('private_key')
        
        if not certificate_file or not private_key_file:
            return jsonify({'success': False, 'message': 'Both public ID and secret key files are required'})
        
        cert_data = certificate_file.read()
        private_key_data = private_key_file.read()
        
        if not ca.verify_certificate(cert_data):
            DatabaseManager.log_action(user[0], 'LOGIN_FAILED', 'Public ID verification failed', request.remote_addr)
            return jsonify({'success': False, 'message': 'Public ID verification failed: Certificate not trusted'})
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=password.encode(),
                backend=default_backend()
            )
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            public_key = certificate.public_key()
            
            challenge = secrets.token_bytes(32)
            signature = private_key.sign(
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            public_key.verify(
                signature,
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except ValueError as e:
            DatabaseManager.log_action(user[0], 'LOGIN_FAILED', f'Secret key decryption failed: {str(e)}', request.remote_addr)
            return jsonify({'success': False, 'message': f'Secret key decryption failed: Invalid password or corrupted key'})
        except Exception as e:
            DatabaseManager.log_action(user[0], 'LOGIN_FAILED', f'Secret key verification failed: {str(e)}', request.remote_addr)
            return jsonify({'success': False, 'message': f'Secret key verification failed: Key does not match public ID ({str(e)})'})
        
        session['user_id'] = user[0]
        session['username'] = username
        session['role'] = user[2]
        DatabaseManager.log_action(user[0], 'LOGIN_SUCCESS', 'User logged in with keys', request.remote_addr)
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': f'Login failed: {str(e)}'})
    

# ... (existing code)

@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized access. Admins only.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('add_admin.html')

        password_hash = generate_password_hash(password)

        conn = sqlite3.connect('hospital_portal.db')
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        if cursor.fetchone():
            flash('Username or email already exists.', 'danger')
            conn.close()
            return render_template('add_admin.html')

        # Insert new admin
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'admin')
        """, (username, email, password_hash))
        conn.commit()
        conn.close()

        flash('New admin added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_admin.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Fetch user documents
    cursor.execute(
        'SELECT id, filename, original_filename, file_hash, signature, created_at FROM documents WHERE uploader_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    )
    documents = [
        {'id': row[0], 'filename': row[1], 'original_filename': row[2], 'file_hash': row[3], 'signature': row[4], 'created_at': row[5]}
        for row in cursor.fetchall()
    ]
    
    # Fetch user data
    cursor.execute('SELECT certificate_path, keys_downloaded FROM users WHERE id = ?', (session['user_id'],))
    user_data = cursor.fetchone()
    
    # Admin-specific data
    all_users = []
    all_documents = []
    if session.get('role') == 'Admin':
        cursor.execute('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC')
        all_users = [
            {'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3], 'created_at': row[4]}
            for row in cursor.fetchall()
        ]
        cursor.execute('''
            SELECT d.id, d.filename, d.original_filename, d.file_hash, d.signature, d.created_at, u.username
            FROM documents d JOIN users u ON d.uploader_id = u.id ORDER BY d.created_at DESC
        ''')
        all_documents = [
            {'id': row[0], 'filename': row[1], 'original_filename': row[2], 'file_hash': row[3], 'signature': row[4], 'created_at': row[5], 'uploader': row[6]}
            for row in cursor.fetchall()
        ]
    
    conn.close()
    
    cert_expiry = None
    cert_status = 'Valid & Verified'
    if user_data[0]:
        try:
            with open(user_data[0], 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                cert_expiry = cert.not_valid_after.isoformat()
                if not ca.verify_certificate(cert_data):
                    cert_status = 'Not Trusted'
        except Exception as e:
            logger.error(f"Error reading certificate: {str(e)}")
            cert_status = 'Error'
    
    keys_downloaded = user_data[1]
    return render_template(
        'dashboard.html',
        documents=documents,
        all_users=all_users,
        all_documents=all_documents,
        session=session,
        cert_expiry=cert_expiry,
        keys_downloaded=keys_downloaded,
        cert_status=cert_status
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    try:
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(8)}_{filename}"
        file_path = Path(UPLOAD_FOLDER) / unique_filename
        
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO documents (filename, original_filename, file_path, file_hash, uploader_id) VALUES (?, ?, ?, ?, ?)',
            (unique_filename, filename, str(file_path), file_hash, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'DOCUMENT_UPLOADED', f'Document {filename} uploaded', request.remote_addr)
        return jsonify({'success': True, 'message': 'Document uploaded successfully!'})
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'})

@app.route('/sign/<int:doc_id>', methods=['POST'])
def sign_document(doc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT file_path, original_filename FROM documents WHERE id = ? AND uploader_id = ?', 
                      (doc_id, session['user_id']))
        doc = cursor.fetchone()
        if not doc:
            return jsonify({'success': False, 'message': 'Document not found or access denied'})
        
        with open(doc[0], 'rb') as f:
            document_content = f.read()
        
        cursor.execute('SELECT private_key_path, certificate_path FROM users WHERE id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        
        with open(user_data[0], 'rb') as f:
            private_key_data = f.read()
        with open(user_data[1], 'rb') as f:
            cert_data = f.read()
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=request.form.get('password', '').encode(),
                backend=default_backend()
            )
            # Validate and log certificate before encoding
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            logger.debug(f"Certificate data (first 100 bytes): {cert_data[:100]}")
        except ValueError as e:
            return jsonify({'success': False, 'message': f'Invalid certificate or password for secret key: {str(e)}'})
        
        signature = DocumentSigner.sign_document(document_content, private_key)
        cert_b64 = base64.b64encode(cert_data).decode('utf-8')
        cursor.execute(
            'UPDATE documents SET signature = ?, signer_certificate = ? WHERE id = ?',
            (signature, cert_b64, doc_id)
        )
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'DOCUMENT_SIGNED', f'Document {doc[1]} signed', request.remote_addr)
        return jsonify({'success': True, 'message': 'Document signed successfully!'})
        
    except Exception as e:
        logger.error(f"Signing error: {str(e)}")
        return jsonify({'success': False, 'message': f'Signing failed: {str(e)}'})

@app.route('/verify/<int:doc_id>', methods=['POST'])
def verify_document(doc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT file_path, signature, signer_certificate, original_filename FROM documents WHERE id = ?', (doc_id,))
        doc = cursor.fetchone()
        conn.close()
        
        if not doc or not doc[1]:
            return jsonify({'success': False, 'message': 'Document not found or not signed'})
        
        with open(doc[0], 'rb') as f:
            document_content = f.read()
        
        cert_data = base64.b64decode(doc[2])  # Decode base64-encoded certificate
        logger.debug(f"Decoded cert_data (first 100 bytes): {cert_data[:100]}")
        is_valid = DocumentSigner.verify_signature(document_content, doc[1], cert_data)
        cert_valid = ca.verify_certificate(cert_data)
        
        if is_valid and cert_valid:
            message = f'â�� Document "{doc[3]}" signature is VALID and certificate is trusted!'
        elif is_valid:
            message = f'â� ï¸� Document "{doc[3]}" signature is valid but certificate is not trusted! Please reissue your certificate.'
        else:
            message = f'â�� Document "{doc[3]}" signature is INVALID!'
        
        DatabaseManager.log_action(session['user_id'], 'SIGNATURE_VERIFIED', f'Signature verification for {doc[3]}: is_valid={is_valid}, cert_valid={cert_valid}', request.remote_addr)
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        return jsonify({'success': False, 'message': f'Verification failed: {str(e)}'})

@app.route('/download/<int:doc_id>')
def download_document(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        if session.get('role') == 'Admin':
            cursor.execute('SELECT file_path, original_filename FROM documents WHERE id = ?', (doc_id,))
        else:
            cursor.execute('SELECT file_path, original_filename FROM documents WHERE id = ? AND uploader_id = ?', 
                          (doc_id, session['user_id']))
        doc = cursor.fetchone()
        conn.close()
        
        if not doc:
            flash('Document not found or access denied')
            return redirect(url_for('dashboard'))
        
        DatabaseManager.log_action(session['user_id'], 'DOCUMENT_DOWNLOADED', f'Document {doc[1]} downloaded', request.remote_addr)
        return send_file(doc[0], as_attachment=True, download_name=doc[1])
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash(f'Download failed: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/download_certificate')
def download_certificate():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT certificate_path, username FROM users WHERE id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and user_data[0]:
            if not Path(user_data[0]).exists():
                logger.error(f"Public ID file not found at {user_data[0]}")
                flash('Public ID file not found on server')
                return redirect(url_for('dashboard'))
            DatabaseManager.log_action(session['user_id'], 'CERTIFICATE_DOWNLOADED', 'User public ID downloaded', request.remote_addr)
            return send_file(user_data[0], as_attachment=True, download_name=f'{user_data[1]}_public_id.pem')
        else:
            logger.error("Public ID path not found in database")
            flash('Public ID not found')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Public ID download error: {str(e)}")
        flash(f'Public ID download failed: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/download_private_key', methods=['POST'])
def download_private_key():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    try:
        password = request.form.get('password', '')
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT private_key_path, username, password_hash, keys_downloaded FROM users WHERE id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        
        if not user_data:
            logger.error("User data not found in database")
            return jsonify({'success': False, 'message': 'User data not found'})
        
        if not check_password_hash(user_data[2], password):
            logger.warning(f"Invalid password for user {user_data[1]} during secret key download")
            return jsonify({'success': False, 'message': 'Invalid password'})
        
        if not user_data[0]:
            logger.error("Secret key path not found in database")
            return jsonify({'success': False, 'message': 'Secret key not found in database'})
        
        private_key_path = Path(user_data[0])
        if not private_key_path.exists():
            logger.error(f"Secret key file not found at {private_key_path}")
            return jsonify({'success': False, 'message': 'Secret key file not found on server'})
        
        try:
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
            serialization.load_pem_private_key(
                private_key_data,
                password=password.encode(),
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Failed to validate secret key: {str(e)}")
            return jsonify({'success': False, 'message': f'Invalid secret key or password: {str(e)}'})
        
        cursor.execute('UPDATE users SET keys_downloaded = 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'PRIVATE_KEY_DOWNLOADED', 'User secret key downloaded', request.remote_addr)
        return send_file(
            private_key_path,
            as_attachment=True,
            download_name=f'{user_data[1]}_secret_key.pem',
            mimetype='application/x-pem-file'
        )
        
    except Exception as e:
        logger.error(f"Secret key download error: {str(e)}")
        return jsonify({'success': False, 'message': f'Secret key download failed: {str(e)}'})

@app.route('/reissue_certificate', methods=['POST'])
def reissue_certificate():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    try:
        password = request.form.get('password', '')
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT username, password_hash, role, private_key_path FROM users WHERE id = ?', (session['user_id'],))
        user_data = cursor.fetchone()
        
        if not user_data:
            return jsonify({'success': False, 'message': 'User data not found'})
        
        if not check_password_hash(user_data[1], password):
            logger.warning(f"Invalid password for user {user_data[0]} during certificate reissue")
            return jsonify({'success': False, 'message': 'Invalid password'})
        
        with open(user_data[3], 'rb') as f:
            private_key_data = f.read()
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=password.encode(),
                backend=default_backend()
            )
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid password for secret key'})
        
        public_key = private_key.public_key()
        certificate_pem = ca.issue_certificate(user_data[0], public_key, user_data[2])
        
        certificate_path = Path(CERTS_FOLDER) / f'{user_data[0]}_public_id.pem'
        with open(certificate_path, 'wb') as f:
            f.write(certificate_pem)
        logger.info(f"Reissued public ID saved at {certificate_path}")
        
        # Update signer_certificate for all documents signed by this user
        cursor.execute('SELECT id FROM documents WHERE uploader_id = ?', (session['user_id'],))
        doc_ids = [row[0] for row in cursor.fetchall()]
        if doc_ids:
            cert_b64 = base64.b64encode(certificate_pem).decode('utf-8')
            cursor.executemany(
                'UPDATE documents SET signer_certificate = ? WHERE id = ?',
                [(cert_b64, doc_id) for doc_id in doc_ids]
            )
        
        cursor.execute('UPDATE users SET certificate_path = ?, keys_downloaded = 0 WHERE id = ?', 
                       (str(certificate_path), session['user_id']))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'CERTIFICATE_REISSUED', f'Certificate reissued for user {user_data[0]}', request.remote_addr)
        return jsonify({'success': True, 'message': 'Certificate reissued successfully! Please download your new public ID.'})
        
    except Exception as e:
        logger.error(f"Certificate reissue error: {str(e)}")
        return jsonify({'success': False, 'message': f'Certificate reissue failed: {str(e)}'})

@app.route('/admin/assign_role/<int:user_id>', methods=['POST'])
@require_admin
def assign_role(user_id):
    try:
        new_role = request.form['role']
        if new_role != 'Admin':
            return jsonify({'success': False, 'message': 'Only Admin role can be assigned by this action.'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        if user[2] == 'Admin':
            return jsonify({'success': False, 'message': f'User {user[1]} is already an Admin'})
        
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'ROLE_ASSIGNED', f'Admin role assigned to user {user[1]} by {session["username"]}', request.remote_addr)
        return jsonify({'success': True, 'message': f'Admin role assigned to user {user[1]} successfully!'})
        
    except Exception as e:
        logger.error(f"Role assignment error: {str(e)}")
        return jsonify({'success': False, 'message': f'Role assignment failed: {str(e)}'})

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    role_in_session = session.get('role', '').lower()
    print(f"Session role: {role_in_session}")  # should show 'admin'

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized access'})

    if role_in_session != 'admin':
        return jsonify({'success': False, 'message': 'Only admins can edit roles'})

    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')

    if not username or not email or not role:
        return jsonify({'success': False, 'message': 'Missing form data'})

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?', (username, email, role, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating user: {str(e)}'})

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@require_admin
def delete_user(user_id):
    try:
        if user_id == session['user_id']:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'})
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT username, certificate_path, private_key_path FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Delete associated documents and files
        cursor.execute('SELECT file_path FROM documents WHERE uploader_id = ?', (user_id,))
        for row in cursor.fetchall():
            try:
                Path(row[0]).unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Failed to delete document file {row[0]}: {str(e)}")
        
        # Delete certificate and private key files
        try:
            if user[1]:
                Path(user[1]).unlink(missing_ok=True)
            if user[2]:
                Path(user[2]).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to delete user files for {user[1]}: {str(e)}")
        
        cursor.execute('DELETE FROM documents WHERE uploader_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'USER_DELETED', f'User {user[0]} deleted', request.remote_addr)
        return jsonify({'success': True, 'message': f'User {user[0]} deleted successfully!'})
        
    except Exception as e:
        logger.error(f"User delete error: {str(e)}")
        return jsonify({'success': False, 'message': f'Delete failed: {str(e)}'})

@app.route('/admin/edit_document/<int:doc_id>', methods=['POST'])
@require_admin
def edit_document(doc_id):
    try:
        original_filename = request.form['original_filename']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT original_filename FROM documents WHERE id = ?', (doc_id,))
        doc = cursor.fetchone()
        if not doc:
            return jsonify({'success': False, 'message': 'Document not found'})
        
        cursor.execute('UPDATE documents SET original_filename = ? WHERE id = ?', (original_filename, doc_id))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'DOCUMENT_EDITED', f'Document {doc[0]} edited to {original_filename}', request.remote_addr)
        return jsonify({'success': True, 'message': f'Document {original_filename} updated successfully!'})
        
    except Exception as e:
        logger.error(f"Document edit error: {str(e)}")
        return jsonify({'success': False, 'message': f'Edit failed: {str(e)}'})

@app.route('/admin/delete_document/<int:doc_id>', methods=['POST'])
@require_admin
def delete_document(doc_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT original_filename, file_path FROM documents WHERE id = ?', (doc_id,))
        doc = cursor.fetchone()
        if not doc:
            return jsonify({'success': False, 'message': 'Document not found'})
        
        try:
            Path(doc[1]).unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Failed to delete document file {doc[1]}: {str(e)}")
        
        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        conn.close()
        
        DatabaseManager.log_action(session['user_id'], 'DOCUMENT_DELETED', f'Document {doc[0]} deleted', request.remote_addr)
        return jsonify({'success': True, 'message': f'Document {doc[0]} deleted successfully!'})
        
    except Exception as e:
        logger.error(f"Document delete error: {str(e)}")
        return jsonify({'success': False, 'message': f'Delete failed: {str(e)}'})

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        DatabaseManager.log_action(user_id, 'LOGOUT', 'User logged out', request.remote_addr)
    
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    try:
        port = find_available_port(DEFAULT_PORT, MAX_PORT_ATTEMPTS)
        print("Starting Secure Hospital Portal...")
        print(f"Server starting on http://localhost:{port}")
        print("   Note: Use HTTPS in production with proper SSL certificates")
        app.run(debug=True, host='0.0.0.0', port=port)
    except RuntimeError as e:
        logger.error(str(e))
        print(f"Error: {str(e)}")
        print("Please free up ports or try again later.")