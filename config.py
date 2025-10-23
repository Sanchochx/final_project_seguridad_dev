import os 

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'una_clave_secreta_segura') 
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/college_student_election' 
    SQLALCHEMY_TRACK_MODIFICATIONS = False