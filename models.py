from datetime import datetime
from flask_login import UserMixin
from extensions import db, bcrypt

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(50), nullable=False, default='viewer')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class FileRecord(db.Model):
    __tablename__ = 'file_records'
    id           = db.Column(db.Integer, primary_key=True)
    filename     = db.Column(db.String(255), nullable=False)
    file_path    = db.Column(db.String(500), nullable=False)
    wrapped_key  = db.Column(db.LargeBinary, nullable=False)
    owner_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref='files')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id             = db.Column(db.Integer, primary_key=True)
    action         = db.Column(db.String(50), nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_id        = db.Column(db.Integer, db.ForeignKey('file_records.id'), nullable=True)
    file_path      = db.Column(db.String(500), nullable=False)
    hmac_signature = db.Column(db.String(64), nullable=False)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')
    file = db.relationship('FileRecord', backref='logs')

    @classmethod
    def create(cls, *, action, user_id, file_id=None, file_path='', hmac_signature=''):
        entry = cls(
            action         = action,
            user_id        = user_id,
            file_id        = file_id,
            file_path      = file_path,
            hmac_signature = hmac_signature,
            timestamp      = datetime.utcnow()
        )
        db.session.add(entry)
        db.session.commit()
        return entry
