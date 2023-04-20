
from app import db

class Manager(db.Model):
    __tablename__ = 'managers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    age = db.Column(db.Integer)
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(50))
    date_of_birth = db.Column(db.String(20))
    address = db.Column(db.String(200))
    password = db.Column(db.String(200)) 
    # jobs = db.relationship('Job', backref='manager', lazy=True)
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'mobile': self.mobile,
            'email': self.email,
            'date_of_birth': self.date_of_birth,
            'address': self.address,
            # "job": [job.to_dict() for job in self.jobs]
        } 