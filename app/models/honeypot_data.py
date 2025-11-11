from app.database import db

severity_enum = db.Enum('low','medium','high','critical',
                        name='severity_type', native_enum=False)

class HoneypotData(db.Model):
    __tablename__ = "honeypot_data"

    honeypot_id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=False),
                          server_default=db.func.now(), nullable=False)

    attacker_ip = db.Column(db.String(45), nullable=False)
    attack_id = db.Column(
        db.Integer,
        db.ForeignKey("attack_types.attack_id", onupdate="CASCADE", ondelete="RESTRICT"),
        nullable=False
    )

    payload = db.Column(db.Text)
    captured_file = db.Column(db.String(255))
    severity = db.Column(severity_enum, nullable=False, server_default='medium')

    attack = db.relationship("AttackType", backref=db.backref("honeypot_logs", lazy="dynamic"))
