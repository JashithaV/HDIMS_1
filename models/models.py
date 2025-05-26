from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# ✅ Hospital model
class Hospital(db.Model):
    __tablename__ = 'hospitals'  # Make sure this matches the FK reference
    hospital_id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=True)

    def __init__(self, hospital_id, name, location=None):
        self.hospital_id = hospital_id
        self.name = name
        self.location = location

# ✅ User model with foreign key
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    hospital_id = db.Column(db.String(20), db.ForeignKey('hospitals.hospital_id'), nullable=True)

    def __init__(self, role, username, email, password, hospital_id=None):
        self.role = role
        self.username = username
        self.email = email
        self.password = password
        self.hospital_id = hospital_id
