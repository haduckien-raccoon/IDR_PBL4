from app.database import db

severity_enum   = db.Enum('low','medium','high','critical',
                          name='severity_type', native_enum=False)
detected_by_enum = db.Enum('AI','Signature','Manual',
                           name='detected_by_type', native_enum=False)
status_enum     = db.Enum('new','investigating','resolved',
                          name='status_type', native_enum=False)

class Event(db.Model):
    __tablename__ = "events"

    event_id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=False),
                          server_default=db.func.now(), nullable=False)

    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)

    attack_id = db.Column(
        db.Integer,
        db.ForeignKey("attack_types.attack_id", onupdate="CASCADE", ondelete="RESTRICT"),
        nullable=False
    )

    severity = db.Column(severity_enum, nullable=False)
    description = db.Column(db.Text)
    detected_by = db.Column(detected_by_enum, nullable=False, server_default='AI')
    status = db.Column(status_enum, nullable=False, server_default='new')

    attack = db.relationship("AttackType", backref=db.backref("events", lazy="dynamic"))
    alerts = db.relationship("Alert", back_populates="event", cascade="all, delete-orphan")
    ai_analyses = db.relationship("AIAnalysis", back_populates="event", cascade="all, delete-orphan")
    incident_reports = db.relationship("IncidentReport", back_populates="event", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Event {self.event_id} sev={self.severity} {self.source_ip}->{self.destination_ip}>"
