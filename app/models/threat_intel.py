'''定时同步'''
from datetime import datetime, timezone
from app.extensions import db

class ThreatIntel(db.Model):
    __tablename__ = 'threat_intels'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    cvss_score = db.Column(db.Float)
    severity = db.Column(db.String(20))
    published_date = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<CVE {self.cve_id} ({self.severity})>'

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None
        }