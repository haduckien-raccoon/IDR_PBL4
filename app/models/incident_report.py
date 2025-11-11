# incident_report.py
from app.database import db

class IncidentReport(db.Model):
    __tablename__ = "incident_reports"

    report_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.Integer,
        db.ForeignKey("events.event_id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False
    )
    report_details = db.Column(db.Text, nullable=False)
    reported_by = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", onupdate="CASCADE", ondelete="SET NULL")
    )
    created_at = db.Column(db.DateTime(timezone=False),
                           server_default=db.func.now(), nullable=False)

    # Dòng thêm vào (Added lines)
    event = db.relationship("Event", back_populates="incident_reports")
    reporter = db.relationship("User", backref=db.backref("incident_reports", lazy="dynamic"))