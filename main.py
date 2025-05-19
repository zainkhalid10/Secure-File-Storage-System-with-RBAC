import os
import uuid
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file
)
from flask_migrate   import Migrate
from flask_wtf       import CSRFProtect
from flask_talisman  import Talisman
from flask_login     import (
    login_user, logout_user,
    login_required, current_user
)
from werkzeug.utils  import secure_filename
from sqlalchemy.exc  import OperationalError

from extensions       import db, bcrypt, login_manager
from models           import User, FileRecord, AuditLog
from decorators       import role_required
from file_encryption  import aes_encrypt, aes_decrypt
from rsa_key_manager  import generate_rsa_keys, encrypt_key, decrypt_key
from encryption       import generate_hmac_sha256

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # ─── Config ───────────────────────────────────────
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET','dev-secret')
    os.makedirs(app.instance_path, exist_ok=True)
    db_path = os.path.join(app.instance_path, 'infop.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ─── Local‐disk folders ───────────────────────────
    UPLOAD_FOLDER    = os.path.join(app.instance_path, 'uploads')
    ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'encrypted')
    DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'decrypted')
    for d in (UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER):
        os.makedirs(d, exist_ok=True)

    # ─── Extensions ───────────────────────────────────
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    Migrate(app, db)
    CSRFProtect(app)
    Talisman(app, force_https=False)   # dev only

    # ─── First‐run setup ─────────────────────────────
    with app.app_context():
        try:
            AuditLog.query.delete()
            FileRecord.query.delete()
            db.session.commit()
        except OperationalError:
            db.create_all()
        generate_rsa_keys()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ─── Routes ───────────────────────────────────────

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=('GET','POST'))
    def register():
        if request.method == 'POST':
            u = request.form['username']
            p = request.form['password']
            r = request.form.get('role','viewer')
            if User.query.filter_by(username=u).first():
                flash('Username already exists','danger')
                return redirect(url_for('register'))
            user = User(username=u, role=r)
            user.set_password(p)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            # log registration
            AuditLog.create(
                action='register',
                user_id=user.id,
                file_id=None,
                file_path=f'user:{user.username}',
                hmac_signature=''
            )
            flash(f'Welcome, {u}!','success')
            return redirect(url_for('dashboard'))
        return render_template('register.html')

    @app.route('/login', methods=('GET','POST'))
    def login():
        if request.method == 'POST':
            u = request.form['username']
            p = request.form['password']
            user = User.query.filter_by(username=u).first()
            if user and user.check_password(p):
                login_user(user)
                # log login
                AuditLog.create(
                    action='login',
                    user_id=user.id,
                    file_id=None,
                    file_path=f'user:{user.username}',
                    hmac_signature=''
                )
                flash(f'Hello again, {u}!','success')
                return redirect(url_for('dashboard'))
            flash('Invalid credentials','danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out','info')
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Admins and editors only see their own uploads;
        # viewers see every encrypted file in the system.
        if current_user.role in ['admin', 'editor']:
            files = (
                FileRecord.query
                .filter_by(owner_id=current_user.id)
                .order_by(FileRecord.created_at.desc())
                .all()
            )
        else:  # viewer
            files = (
                FileRecord.query
                .order_by(FileRecord.created_at.desc())
                .all()
            )

        return render_template('dashboard.html',
                               encrypted_files=files)

    @app.route('/upload', methods=('POST',))
    @login_required
    @role_required(['admin','editor'])
    def upload_file():
        f = request.files.get('file')
        if not f or not f.filename:
            flash('No file selected','danger')
            return redirect(url_for('dashboard'))

        # AES-encrypt in memory
        raw = f.read()
        ciphertext, aes_key = aes_encrypt(raw)
        hmac_sig = generate_hmac_sha256(ciphertext)

        # Wrap key & write ciphertext to disk
        wrapped_key = encrypt_key(aes_key)
        filename    = secure_filename(f.filename)
        tag         = uuid.uuid4().hex
        enc_name    = f"{tag}_{filename}"
        enc_path    = os.path.join(ENCRYPTED_FOLDER, enc_name)
        with open(enc_path, 'wb') as out:
            out.write(ciphertext)

        # Persist metadata
        rec = FileRecord(
            filename    = filename,
            file_path   = enc_path,
            wrapped_key = wrapped_key,
            owner_id    = current_user.id
        )
        db.session.add(rec)
        db.session.commit()

        # log upload
        AuditLog.create(
            action='upload',
            user_id=current_user.id,
            file_id=rec.id,
            file_path=enc_path,
            hmac_signature=hmac_sig
        )
        # log encrypt
        AuditLog.create(
            action='encrypt',
            user_id=current_user.id,
            file_id=None,
            file_path=filename,
            hmac_signature=hmac_sig
        )

        flash('File encrypted & stored. Click “Download Encrypted” to fetch it.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/download/encrypted/<int:file_id>')
    @login_required
    def download_encrypted(file_id):
        rec = FileRecord.query.get_or_404(file_id)
        with open(rec.file_path, 'rb') as fh:
            ciphertext = fh.read()
        hmac_sig = generate_hmac_sha256(ciphertext)
        AuditLog.create(
            action='download_encrypted',
            user_id=current_user.id,
            file_id=rec.id,
            file_path=rec.file_path,
            hmac_signature=hmac_sig
        )
        return send_file(
            rec.file_path,
            as_attachment=True,
            download_name=f"encrypted_{rec.filename}"
        )

    @app.route('/download/decrypted/<int:file_id>')
    @login_required
    def download_decrypted(file_id):
        rec = FileRecord.query.get_or_404(file_id)
        with open(rec.file_path, 'rb') as fh:
            ciphertext = fh.read()
        aes_key   = decrypt_key(rec.wrapped_key)
        plaintext = aes_decrypt(ciphertext, aes_key)
        hmac_sig  = generate_hmac_sha256(plaintext)
        # log decrypt
        AuditLog.create(
            action='decrypt',
            user_id=current_user.id,
            file_id=rec.id,
            file_path=rec.file_path,
            hmac_signature=hmac_sig
        )
        # log download_decrypted
        AuditLog.create(
            action='download_decrypted',
            user_id=current_user.id,
            file_id=rec.id,
            file_path=rec.file_path,
            hmac_signature=hmac_sig
        )
        buf = BytesIO(plaintext); buf.seek(0)
        return send_file(
            buf,
            as_attachment=True,
            download_name=f"decrypted_{rec.filename}"
        )

    @app.route('/view_logs')
    @login_required
    def view_logs():
        logs = (AuditLog.query
                .filter_by(user_id=current_user.id)
                .order_by(AuditLog.timestamp.asc())
                .all())
        return render_template('view_logs.html', logs=logs)

    @app.route('/viewer')
    @login_required
    @role_required(['admin','editor','viewer'])
    def viewer_panel():
        return f"Viewer panel for {current_user.username}"

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
