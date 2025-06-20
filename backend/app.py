from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import base64
from cryptography.fernet import Fernet
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Encryption key for URLs
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'ops' or 'client'
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    uploader = db.relationship('User', backref=db.backref('uploaded_files', lazy=True))

class DownloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    downloaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    file = db.relationship('File', backref=db.backref('download_logs', lazy=True))
    user = db.relationship('User', backref=db.backref('downloads', lazy=True))

# Helper Functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_verification_email(email, verification_url):
    # In production, implement actual email sending
    print(f"Verification email would be sent to {email}")
    print(f"Verification URL: {verification_url}")
    return True

def generate_encrypted_download_url(file_id, user_id):
    # Create payload with file_id, user_id, and expiration
    payload = f"{file_id}:{user_id}:{datetime.utcnow().timestamp() + 86400}"  # 24 hours
    encrypted_payload = cipher_suite.encrypt(payload.encode())
    return base64.urlsafe_b64encode(encrypted_payload).decode()

def decrypt_download_url(encrypted_url):
    try:
        encrypted_payload = base64.urlsafe_b64decode(encrypted_url.encode())
        decrypted_payload = cipher_suite.decrypt(encrypted_payload).decode()
        file_id, user_id, expiration = decrypted_payload.split(':')
        
        # Check if URL has expired
        if float(expiration) < datetime.utcnow().timestamp():
            return None, None, "URL has expired"
            
        return int(file_id), int(user_id), None
    except Exception as e:
        return None, None, "Invalid URL"

# API Routes

@app.route('/')
def index():
    return "Welcome to the Secure File Sharing API. Please use the API endpoints."

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')
    
    if not email or not password or not user_type:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    user = User.query.filter_by(email=email, user_type=user_type).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    if user_type == 'client' and not user.is_verified:
        return jsonify({'success': False, 'message': 'Please verify your email first'}), 401
    
    access_token = create_access_token(identity=str(user.id))
    
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': access_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'type': user.user_type
        }
    })

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password or not name:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'}), 400
    
    # Generate verification token
    verification_token = secrets.token_urlsafe(32)
    
    # Create new user
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        name=name,
        user_type='client',
        verification_token=verification_token
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Generate encrypted verification URL
    verification_payload = f"verify:{user.id}:{verification_token}"
    encrypted_verification = cipher_suite.encrypt(verification_payload.encode())
    encrypted_url = f"http://localhost:5001/api/auth/verify/{base64.urlsafe_b64encode(encrypted_verification).decode()}"
    
    # Send verification email (mock)
    send_verification_email(email, encrypted_url)
    
    return jsonify({
        'success': True,
        'message': 'Account created successfully. Please check your email for verification.',
        'encrypted_url': encrypted_url
    })

@app.route('/api/auth/verify/<encrypted_token>', methods=['GET'])
def verify_email(encrypted_token):
    try:
        encrypted_payload = base64.urlsafe_b64decode(encrypted_token.encode())
        decrypted_payload = cipher_suite.decrypt(encrypted_payload).decode()
        
        if not decrypted_payload.startswith('verify:'):
            return jsonify({'success': False, 'message': 'Invalid verification token'}), 400
        
        _, user_id, verification_token = decrypted_payload.split(':')
        
        user = User.query.filter_by(id=int(user_id), verification_token=verification_token).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid verification token'}), 400
        
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Email verified successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Invalid verification token'}), 400

@app.route('/api/files/upload', methods=['POST'])
@jwt_required()
def upload_file():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'ops':
        return jsonify({'success': False, 'message': 'Only operations users can upload files'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Only PPTX, DOCX, and XLSX files are allowed'}), 400
    
    # Generate unique filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4()}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save file
    file.save(file_path)
    
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Save file info to database
    file_record = File(
        filename=filename,
        original_filename=file.filename,
        file_type=file.content_type,
        file_size=file_size,
        uploaded_by=current_user_id
    )
    
    db.session.add(file_record)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'File uploaded successfully',
        'file': {
            'id': file_record.id,
            'name': file_record.original_filename,
            'size': file_record.file_size,
            'type': file_record.file_type
        }
    })

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'client':
        return jsonify({'success': False, 'message': 'Only client users can list files'}), 403
    
    files = File.query.all()
    
    file_list = []
    for file in files:
        file_list.append({
            'id': file.id,
            'name': file.original_filename,
            'type': file.file_type,
            'size': file.file_size,
            'uploaded_at': file.uploaded_at.isoformat(),
            'uploaded_by': file.uploader.name
        })
    
    return jsonify({
        'success': True,
        'data': file_list,
        'message': 'Files retrieved successfully'
    })

@app.route('/api/files/download/<int:file_id>', methods=['GET'])
@jwt_required()
def get_download_url(file_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'client':
        return jsonify({'success': False, 'message': 'Only client users can download files'}), 403
    
    file = File.query.get(file_id)
    if not file:
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    # Generate encrypted download URL
    encrypted_url = generate_encrypted_download_url(file_id, current_user_id)
    download_url = f"http://localhost:5001/api/files/secure-download/{encrypted_url}"
    
    return jsonify({
        'success': True,
        'data': {'download_url': download_url},
        'message': 'Download URL generated successfully'
    })

@app.route('/api/files/secure-download/<encrypted_url>', methods=['GET'])
@jwt_required()
def secure_download(encrypted_url):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'client':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    file_id, url_user_id, error = decrypt_download_url(encrypted_url)
    
    if error:
        return jsonify({'success': False, 'message': error}), 400
    
    if str(url_user_id) != str(current_user_id):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    file = File.query.get(file_id)
    if not file:
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    # Log the download
    download_log = DownloadLog(file_id=file_id, user_id=current_user_id)
    db.session.add(download_log)
    db.session.commit()
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File not found on server'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=file.original_filename)

@app.route('/api/stats/ops', methods=['GET'])
@jwt_required()
def ops_stats():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'ops':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    total_files = File.query.count()
    total_downloads = DownloadLog.query.count()
    
    return jsonify({
        'success': True,
        'data': {
            'total_files': total_files,
            'total_downloads': total_downloads
        }
    })

@app.route('/api/stats/client', methods=['GET'])
@jwt_required()
def client_stats():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.user_type != 'client':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    available_files = File.query.count()
    user_downloads = DownloadLog.query.filter_by(user_id=current_user_id).count()
    
    return jsonify({
        'success': True,
        'data': {
            'available_files': available_files,
            'downloads': user_downloads
        }
    })

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create default ops user if not exists
    if not User.query.filter_by(email='ops@example.com').first():
        ops_user = User(
            email='ops@example.com',
            password_hash=generate_password_hash('password123'),
            name='Operations User',
            user_type='ops',
            is_verified=True
        )
        db.session.add(ops_user)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default ops user if not exists
        if not User.query.filter_by(email='ops@example.com').first():
            ops_user = User(
                email='ops@example.com',
                password_hash=generate_password_hash('password123'),
                name='Operations User',
                user_type='ops',
                is_verified=True
            )
            db.session.add(ops_user)
            db.session.commit()
    
    app.run(debug=True, port=5001)