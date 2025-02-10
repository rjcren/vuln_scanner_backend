'''权限模型'''
from app.extensions import db

class Permission(db.Model):
    __tablename__ = 'permissions'
    perm_id = db.Column(db.Integer, primary_key=True)
    perm_name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f'<Permission {self.perm_name}>'