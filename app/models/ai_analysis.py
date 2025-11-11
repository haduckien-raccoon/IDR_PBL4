# ai_analysis.py
from app.database import db

prediction_enum = db.Enum('Malicious', 'Benign', 'Suspicious',
                          name='prediction_type', native_enum=False)

class AIAnalysis(db.Model):
    __tablename__ = "ai_analysis"

    analysis_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.Integer,
        db.ForeignKey("events.event_id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False
    )

    model_used = db.Column(db.String(100), nullable=False)
    prediction = db.Column(prediction_enum, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    analysis_time = db.Column(db.DateTime(timezone=False),
                              server_default=db.func.now(), nullable=False)

    # Dòng thêm vào (Added line)
    event = db.relationship("Event", back_populates="ai_analyses")