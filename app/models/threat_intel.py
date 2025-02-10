'''威胁情报模型'''
from datetime import datetime
from app.extensions import db

class ThreatIntel(db.Model):
    __tablename__ = 'threat_intels'
    intel_id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    published_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatIntel {self.cve_id}>'