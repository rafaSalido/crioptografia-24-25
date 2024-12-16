from flask_sqlalchemy import SQLAlchemy
from db.database import db
from sqlalchemy.dialects.postgresql import JSON  # Asegúrate de importar JSON si tu base de datos lo soporta

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
    public_key_kyber = db.Column(db.Text, nullable=False)  # Clave pública Kyber512
    private_key_kyber = db.Column(db.Text, nullable=False)  # Clave privada Kyber512
    certificate_path = db.Column(db.String(250), nullable=True)  # Guardar la ruta del certificado

    def add_user(self, user_id):
        """
        Añadir un usuario a la comunidad.
        """
        new_member = CommunityUser(user_id=user_id, community_id=self.id)
        db.session.add(new_member)
        db.session.commit()

    def is_member(self, user_id):
        """
        Verificar si un usuario es miembro de la comunidad.
        """
        return CommunityUser.query.filter_by(user_id=user_id, community_id=self.id).first() is not None

    def get_members(self):
        """
        Obtener todos los miembros de la comunidad.
        """
        return [user.user for user in self.community_users]


class CommunityUser(db.Model):
    __tablename__ = 'community_users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    
    user = db.relationship('User', backref='community_users')
    community = db.relationship('Community', backref='community_users')


class CommunityFiles(db.Model):
    __tablename__ = 'community_files'

    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    file_name = db.Column(db.String(150), nullable=False)
    file_path = db.Column(db.String(250), nullable=False)
    encrypted_aes_keys = db.Column(JSON, nullable=False)  # Cambiar Text a JSON para facilitar la gestión de claves

    community = db.relationship('Community', backref='community_files')

    def add_encrypted_key_for_member(self, user_id, encrypted_key):
        """
        Añadir una clave AES cifrada para un miembro de la comunidad.
        """
        if not self.encrypted_aes_keys:
            self.encrypted_aes_keys = {}
        self.encrypted_aes_keys[str(user_id)] = encrypted_key
        db.session.commit()