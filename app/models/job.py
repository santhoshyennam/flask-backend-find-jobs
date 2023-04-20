
from app import db


class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    salary = db.Column(db.String(20))
    company = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    description = db.Column(db.String(2000))
    email = db.Column(db.String(50))
    created_by = db.Column(db.Integer, db.ForeignKey('managers.id'), nullable=False)
    category = db.relationship('Category', backref='category', lazy=True)
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'salary': self.salary,
            'company': self.company,
            'category_id': self.category_id,
            'description': self.description,
            'email': self.email,
            'created_by': self.created_by,
            'category': self.category.to_dict() if self.category else None
            # "manager": self.created_by.to_dict()
        }