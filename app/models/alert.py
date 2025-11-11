from app.database import db
from sqlalchemy import text

alert_level_enum = db.Enum(
    'info', 'warning', 'critical',
    name='alert_level_type', native_enum=False
)

class Alert(db.Model):
    __tablename__ = "alerts"

    alert_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.Integer,
        db.ForeignKey("events.event_id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False
    )
    alert_message = db.Column(db.Text, nullable=False)
    alert_level = db.Column(alert_level_enum, nullable=False, server_default='info')
    sent_at = db.Column(db.DateTime(timezone=False),
                        server_default=db.func.now(), nullable=False)
    is_sent = db.Column(db.Boolean, nullable=False, server_default=text("0"))
    is_read = db.Column(db.Boolean, nullable=False, server_default=text("0"))

    event = db.relationship("Event", back_populates="alerts")
