from app.database import db

role_enum = db.Enum('admin', 'analyst', 'user',
                    name='role_type', native_enum=False)

class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    role = db.Column(role_enum, nullable=False, server_default='user')
    created_at = db.Column(db.DateTime(timezone=False),
                           server_default=db.func.now(), nullable=False)
