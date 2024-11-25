from flask_sqlalchemy import SQLAlchemy
from db.database import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key_kyber = db.Column(db.Text, nullable=False)  # Clave pública Kyber512
    private_key_kyber = db.Column(db.Text, nullable=False)  # Clave privada Kyber512
    certificate_dilithium = db.Column(db.Text, nullable=False)  # Dilithium certificate



class Community(db.Model):
    __tablename__ = 'communities'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    


class CommunityUser(db.Model):
    __tablename__ = 'community_users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    
    user = db.relationship('User', backref='community_users')
    community = db.relationship('Community', backref='community_users')