from flask_sqlalchemy import SQLAlchemy
from db.database import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key_kyber = db.Column(db.Text, nullable=False)  # Clave pública Kyber512
    private_key_kyber = db.Column(db.Text, nullable=False)  # Clave privada Kyber512
