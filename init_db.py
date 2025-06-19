from app import db, app

with app.app_context():
   # Only create tables if they don't exist (safe for production)
   db.create_all()
   print("Database tables created successfully!")