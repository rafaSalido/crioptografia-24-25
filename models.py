from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.Text, nullable=True)  # Añadir esta columna para la clave pública
    private_key = db.Column(db.Text, nullable=True)  # Añadir esta columna para la clave privada
