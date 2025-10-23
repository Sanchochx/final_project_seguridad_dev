from models import db, User, UserRole
from app import app

with app.app_context():
    db.create_all()
    
    admin_user = User.query.filter_by(username="adminj").first()
    
    if not admin_user:
        admin_user = User(username="admin",role=UserRole.ADMIN)  
        admin_user.set_password("sancho")
        db.session.add(admin_user)
        db.session.commit()
        print("Usuario admin creado con éxito.")
    else:
        print("El usuario admin ya existe.")
