from app.database import db

class AttackType(db.Model):
    __tablename__ = "attack_types"  # 👈 chữ thường

    attack_id = db.Column(db.Integer, primary_key=True)
    attack_name = db.Column(db.String(100), nullable=False, unique=True)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)

    def __repr__(self):
        return f"<AttackType {self.attack_id} {self.attack_name}>"

    def to_dict(self):
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "category": self.category,
            "description": self.description,
        }
