'''角色权限关联表'''
from app.extensions import db

role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('perm_id', db.Integer, db.ForeignKey('permissions.perm_id'), primary_key=True)
)

class Role(db.Model):
    # ... 其他字段
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')