# College Student Election System - Sistema de Votación Electrónica

A secure web-based electronic voting system for college student elections, built with Flask and MySQL. This application provides a complete solution for managing student elections with role-based access control, candidate registration, voting, and comprehensive audit logging.

## Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [User Roles](#user-roles)
- [Security Features](#security-features)
- [Documentation](#documentation)
- [License](#license)

## Features

### Core Features
- **User Authentication & Authorization**: Secure login system with role-based access control (Admin, Teacher, Student)
- **Candidate Management**: Admin can register candidates with profiles and proposals
- **Voting System**: Students can cast votes for their preferred candidates
- **Results Display**: Real-time voting results with percentages and vote counts
- **User Management**: Admin can create, edit, and delete users
- **Profile Management**: Users can update their profile information and pictures

### Security Features
- CSRF protection on all forms
- Password hashing using Werkzeug security
- reCAPTCHA integration for login protection
- Failed login attempt tracking with automatic blocking
- Audit logging for username and password changes
- One vote per user enforcement

### Administrative Features
- User management dashboard with search and filter
- Comprehensive audit logs for username and password changes
- Export logs to PDF and Excel formats
- Candidate registration and management
- Role-based user creation

## Technology Stack

- **Backend Framework**: Flask (Python)
- **Database**: MySQL with SQLAlchemy ORM
- **Authentication**: Flask-Login
- **Forms**: Flask-WTF with CSRF protection
- **File Uploads**: Flask-Reuploads
- **PDF Generation**: ReportLab
- **Excel Generation**: OpenPyXL
- **Security**: Werkzeug, reCAPTCHA

## Project Structure

```
final_project_seguridad_dev/
├── app.py                 # Main application file with routes
├── models.py              # Database models (User, Candidate, Vote, etc.)
├── forms.py               # WTForms form definitions
├── config.py              # Application configuration
├── create_admin.py        # Script to create initial admin user
├── password.py            # Utility for generating encryption keys
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (not in git)
├── static/               # Static files (CSS, images, candidate photos)
│   ├── css/
│   ├── images/
│   └── candidate_photos/
├── templates/            # HTML templates
│   ├── login.html
│   ├── index.html
│   ├── vote.html
│   ├── results.html
│   ├── manage_users.html
│   └── ...
└── uploads/             # User uploaded files
    └── photos/
```

## Installation

### Prerequisites
- Python 3.8 or higher
- MySQL Server
- pip (Python package manager)

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd final_project_seguridad_dev
```

### Step 2: Create Database
Create a MySQL database for the application:
```sql
CREATE DATABASE college_student_election;
```

**Note**: The tables will be created automatically by the application on first run.

### Step 3: Install Dependencies
Install all required Python libraries:
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
Create a `.env` file in the project root (if not exists) and configure:
```
SECRET_KEY=your_secret_key_here
```

Update `config.py` with your MySQL credentials if needed:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/college_student_election'
```

### Step 5: Create Initial Admin User
Run the admin creation script:
```bash
python create_admin.py
```

This creates an admin user with:
- Username: `admin`
- Password: `sancho` (change this immediately after first login)

### Step 6: Run the Application
```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`

## Configuration

### Database Configuration
Edit `config.py` to update database connection:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://user:password@host/database_name'
```

### reCAPTCHA Configuration
Update the reCAPTCHA secret key in `app.py` (line 138):
```python
RECAPTCHA_SECRET_KEY = 'your_recaptcha_secret_key'
```

Also update the site key in `templates/login.html`.

### Upload Configuration
File upload settings are configured in `app.py`:
- Profile photos: `uploads/photos/`
- Candidate photos: `static/candidate_photos/`
- Allowed formats: JPG, JPEG, PNG, WEBP

## Usage

### Admin Users
Admins have full access to:
1. **User Management**: Create users (students, teachers, admins) via `/register/<role>`
2. **Candidate Registration**: Register candidates via `/register_candidate`
3. **User Administration**: Manage users at `/manage_users`
4. **Audit Logs**: View all system logs at `/all_logs`
5. **Export Reports**: Export logs to PDF/Excel format

### Students
Students can:
1. **View Profile**: Check and edit their profile at `/view_profile` and `/edit_profile`
2. **Vote**: Cast their vote at `/vote` (one vote per student)
3. **View Results**: See election results at `/results`
4. **Change Password**: Update password at `/change_password`
5. **Change Username**: Update username at `/edit_username`

### Teachers
Teachers can:
1. **View Profile**: Manage their profile information
2. **View Results**: See election results
3. **View Candidates**: Browse candidate list

## User Roles

The system supports three user roles:

1. **ADMIN**: Full system access
   - User management
   - Candidate registration
   - View all logs
   - Edit any user's credentials

2. **DOCENTE (Teacher)**: Limited access
   - View own profile
   - View candidates
   - View results

3. **ESTUDIANTE (Student)**: Voting access
   - View own profile
   - Vote for candidates (once)
   - View results

## Security Features

### Authentication
- Password hashing using Werkzeug's `generate_password_hash`
- Flask-Login session management
- Protected routes with `@login_required` decorator

### CSRF Protection
- All forms protected with CSRF tokens
- Flask-WTF CSRF implementation

### Failed Login Protection
- Maximum 3 failed login attempts
- 15-second automatic blocking after max attempts
- Tracking stored in `FailedLoginAttempt` model

### Audit Logging
- Username changes logged in `UsernameChangeLog`
- Password changes logged in `PasswordChangeLog`
- Tracks who made the change and who was affected

### Input Validation
- Form validation using WTForms validators
- File type restrictions on uploads
- Email uniqueness validation

## Documentation

For more detailed documentation, see:
- [API Documentation](API_DOCUMENTATION.md) - All routes and endpoints
- [Database Schema](DATABASE_SCHEMA.md) - Database structure and relationships
- [Security Documentation](SECURITY.md) - Security features and best practices
- [Contributing Guidelines](CONTRIBUTING.md) - Development guidelines

## Default Credentials

**Admin Account** (created by `create_admin.py`):
- Username: `admin`
- Password: `sancho`

**IMPORTANT**: Change the default password immediately after first login for security!

## Common Issues

### Database Connection Error
- Verify MySQL is running
- Check database credentials in `config.py`
- Ensure database `college_student_election` exists

### Import Errors
- Run `pip install -r requirements.txt`
- Ensure you're using Python 3.8+

### reCAPTCHA Errors
- Update `RECAPTCHA_SECRET_KEY` in `app.py`
- Update site key in `templates/login.html`

## License

This project is developed for educational purposes.

### --Copyright-- ###

### -------------------- λ-SanchoDev -------------------- ###
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣴⣦⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⠿⠿⠿⠿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣶⡀⠀⠀⠀⠀
⠀⠀⠀⣴⣿⣿⠟⠁⠀⠀⠀⣶⣶⣶⣶⡆⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣦⠀⠀⠀
⠀⠀⣼⣿⣿⠋⠀⠀⠀⠀⠀⠛⠛⢻⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣧⠀⠀
⠀⢸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⡇⠀
⠀⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠀
⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⡟⢹⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⣹⣿⣿⠀
⠀⣿⣿⣷⠀⠀⠀⠀⠀⠀⣰⣿⣿⠏⠀⠀⢻⣿⣿⡄⠀⠀⠀⠀⠀⠀⣿⣿⡿⠀
⠀⢸⣿⣿⡆⠀⠀⠀⠀⣴⣿⡿⠃⠀⠀⠀⠈⢿⣿⣷⣤⣤⡆⠀⠀⣰⣿⣿⠇⠀
⠀⠀⢻⣿⣿⣄⠀⠀⠾⠿⠿⠁⠀⠀⠀⠀⠀⠘⣿⣿⡿⠿⠛⠀⣰⣿⣿⡟⠀⠀
⠀⠀⠀⠻⣿⣿⣧⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠏⠀⠀⠀
⠀⠀⠀⠀⠈⠻⣿⣿⣷⣤⣄⡀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⠟⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣶⣶⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
### -------------------- λ-SanchoDev -------------------- ###