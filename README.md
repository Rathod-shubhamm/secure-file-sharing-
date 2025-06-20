# Secure File Sharing System

A robust, secure file sharing platform built with Flask, SQLAlchemy, and JWT authentication. This system enforces strict user roles: **Ops users** can upload files, while **Client users** can sign up, verify their email, and securely download files via encrypted, user-bound URLs.

---

## Features

- **User Roles**
  - **Ops User**: Can log in and upload files (`.pptx`, `.docx`, `.xlsx` only).
  - **Client User**: Can sign up, verify email, log in, list all files, and download files via secure, encrypted links.

- **Security**
  - JWT-based authentication for all protected endpoints.
  - Role-based access control: Only ops can upload; only clients can download/list files.
  - Download links are encrypted, user-specific, and expire after 24 hours.
  - File uploads restricted to specific document types.

- **Email Verification**
  - Clients must verify their email via a unique, encrypted link sent to their inbox before accessing downloads.

- **Audit Logging**
  - All downloads are logged with user and file details.

---

## Project Structure

secure-file-sharing-/
├── backend/
│ ├── app.py # Main Flask app with all API logic
│ ├── requirements.txt # Python dependencies
│ ├── run.py # Entry point to start the Flask server
│ └── instance/ # SQLite DB and configs
├── uploads/ # Directory for uploaded files
└── frontend.html # (Optional) Demo HTML frontend



---

## API Endpoints

### **Authentication**

- `POST /api/auth/login`  
  Login for both Ops and Client users.  
  **Payload:** `{ "email": "...", "password": "...", "user_type": "ops"|"client" }`

- `POST /api/auth/signup`  
  Sign up as a Client user.  
  **Payload:** `{ "email": "...", "password": "...", "name": "..." }`  
  **Response:** Returns an encrypted verification URL.

- `GET /api/auth/verify/<encrypted_token>`  
  Verifies client email using the encrypted link sent to their email.

---

### **File Management**

- `POST /api/files/upload`  
  **(Ops Only)** Upload a file (`.pptx`, `.docx`, `.xlsx` only).  
  **Headers:** `Authorization: Bearer <token>`  
  **Form-Data:** `file=<file>`

- `GET /api/files`  
  **(Client Only)** List all uploaded files.  
  **Headers:** `Authorization: Bearer <token>`

- `GET /api/files/download/<file_id>`  
  **(Client Only)** Get a secure, encrypted download URL for a file.  
  **Headers:** `Authorization: Bearer <token>`  
  **Response:**  



- `GET /api/files/secure-download/<encrypted_url>`  
**(Client Only)** Download the file via the encrypted, user-bound URL.  
**Headers:** `Authorization: Bearer <token>`

---

### **Stats**

- `GET /api/stats/ops`  
**(Ops Only)** Get total files and downloads.

- `GET /api/stats/client`  
**(Client Only)** Get available files and user's download count.

---

## Security Details

- **File Uploads**: Only `.pptx`, `.docx`, `.xlsx` files are accepted. All files are stored with a UUID filename to prevent enumeration.
- **Download Links**: Encrypted using Fernet, include file ID, user ID, and expiry timestamp. Only the intended client can use the link, and only within 24 hours.
- **JWT Auth**: All protected routes require a valid JWT token.
- **Role Enforcement**: Each endpoint checks user type (ops/client) before allowing access.

---

## Database Models

- **User**: Stores user info, hashed password, role, and verification status.
- **File**: Stores file metadata (name, type, uploader, size, timestamp).
- **DownloadLog**: Records each download event (file, user, time).

---

## Setup & Usage

1. **Clone the repository:**
git clone https://github.com/Rathod-shubhamm/secure-file-sharing-.git
cd secure-file-sharing-/backend

2. **Create a virtual environment and install dependencies:**
python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
pip install -r requirements.txt
3. **Initialize the database:**

from app import db
db.create_all()
exit()


4. **Run the Flask server:**
python run.py


5. **API Usage:**
- Use tools like Postman or cURL to interact with the API endpoints.
- For file uploads, use `multipart/form-data`.
- For all protected endpoints, include the JWT token in the `Authorization` header.

---

## Notes

- The email verification system is mocked for demo purposes (prints to console). Replace with an actual email service for production.
- Update `SECRET_KEY` and `JWT_SECRET_KEY` in `app.py` for production.
- The server runs on `localhost:5001` by default.

---

## License

MIT License

---

## Author

[Shubham Rathod](https://github.com/Rathod-shubhamm)


