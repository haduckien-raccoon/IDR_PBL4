# app/database/__init__.py
# FastAPI-compatible SQLAlchemy shim – giữ API kiểu Flask-SQLAlchemy:
# db.Model, db.metadata, db.Column, db.String, db.Integer, db.Enum, db.ForeignKey, db.relationship, ...

from __future__ import annotations
from typing import Optional

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    Float,
    Enum,
    ForeignKey,
    BigInteger,
    SmallInteger,
    LargeBinary,
    JSON,  # nếu DB không hỗl trợ JSON, bạn có thể bỏ
    func,
)
from sqlalchemy.orm import (
    sessionmaker,
    # [SỬA] Bỏ import scoped_session
    declarative_base,
    relationship,
    backref,
    Session
)

from app.core.config import settings

# --- Base model (tương đương db.Model) ---
Base = declarative_base()

class _DBShim:
    """Giữ API giống Flask-SQLAlchemy để không phải sửa các model hiện có."""
    # Model & metadata
    Model = Base
    
    session = None  # DEPRECATED

    @property
    def metadata(self):
        return Base.metadata

    # Re-export các kiểu & helpers để dùng như db.Column, db.String, db.Enum, ...
    Column = Column
    Integer = Integer
    BigInteger = BigInteger
    SmallInteger = SmallInteger
    String = String
    Text = Text
    DateTime = DateTime
    Boolean = Boolean
    Float = Float
    Enum = Enum
    ForeignKey = ForeignKey
    LargeBinary = LargeBinary
    JSON = JSON
    func = func

    relationship = staticmethod(relationship)
    backref = staticmethod(backref)

db = _DBShim()

_engine = None
_SessionFactory = None

def init_db(app: Optional[object] = None):
    """
    Tương thích:
      - FastAPI: init_db()
      - Flask (cũ): init_db(app) -> 'app' sẽ bị bỏ qua, vẫn hoạt động
    """
    global _engine, _SessionFactory

    db_url = getattr(settings, "DATABASE_URL", None)
    if not db_url and app is not None:
        try:
            cfg = getattr(app, "config", {})
            db_url = cfg.get("SQLALCHEMY_DATABASE_URI") or cfg.get("DATABASE_URL")
        except Exception:
            pass

    if not db_url:
        raise RuntimeError("DATABASE_URL is not configured in settings or app.config")

    _engine = create_engine(
        db_url, 
        pool_pre_ping=True, 
        future=True,
        pool_recycle=300  # Giữ nguyên 5 phút
    )
    
    # [SỬA] Bỏ 'scoped_session', chỉ dùng 'sessionmaker'
    _SessionFactory = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def get_session():
    """
    Dependency cho FastAPI để quản lý session DB.
    Đảm bảo tự động commit, rollback, và close.
    """
    if _SessionFactory is None:
        raise RuntimeError("DB not initialized. Call init_db() first.")
    
    # [SỬA] Lấy session trực tiếp từ sessionmaker
    sess: Session = _SessionFactory() 
    
    try:
        yield sess  # 1. Cung cấp session cho endpoint
        sess.commit() # 2. Commit nếu endpoint chạy xong (không lỗi)
    except Exception:
        sess.rollback() # 3. Rollback nếu có bất kỳ lỗi nào xảy ra
        raise # 4. Ném lỗi đó ra để FastAPI xử lý
    finally:
        # [SỬA] Dùng 'sess.close()' để đóng session này.
        # Không dùng _SessionFactory.remove() nữa.
        sess.close()


from contextlib import contextmanager
@contextmanager
def get_session_context():
    gen = get_session()
    session = next(gen)
    try:
        yield session
        try:
            gen.send(None)  # trigger finally của generator
        except StopIteration:
            pass
    except Exception as e:
        try:
            gen.throw(e)
        except StopIteration:
            pass
        raise
