# setup_db.py

from main import create_app
from extensions import db

app = create_app()

with app.app_context():
    # Completely rebuild all tables
    db.drop_all()
    db.create_all()
    print("✅ Database tables created.")
