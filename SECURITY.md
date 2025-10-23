# Security Documentation - College Student Election System

This document outlines the security features, best practices, and considerations implemented in the College Student Election System.

## Table of Contents
- [Authentication & Authorization](#authentication--authorization)
- [Password Security](#password-security)
- [CSRF Protection](#csrf-protection)
- [Input Validation](#input-validation)
- [Session Management](#session-management)
- [Rate Limiting & Account Lockout](#rate-limiting--account-lockout)
- [Audit Logging](#audit-logging)
- [File Upload Security](#file-upload-security)
- [Database Security](#database-security)
- [reCAPTCHA Integration](#recaptcha-integration)
- [Security Best Practices](#security-best-practices)
- [Known Limitations](#known-limitations)
- [Security Checklist for Deployment](#security-checklist-for-deployment)

---

## Authentication & Authorization

### Flask-Login Integration

The system uses Flask-Login for session-based authentication:

**Implementation:**
```python
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
```

**Features:**
- Session-based authentication with secure cookies
- `@login_required` decorator protects sensitive routes
- Automatic redirect to login page for unauthenticated users
- User loading via `load_user()` callback

### Role-Based Access Control (RBAC)

Three user roles with different permissions:

| Role | Permissions |
|------|-------------|
| **ADMIN** | Full system access: user management, candidate registration, audit logs, all user operations |
| **DOCENTE** | Limited access: view profile, view candidates, view results |
| **ESTUDIANTE** | Voting access: vote once, manage own profile, view results |

**Implementation:**
```python
if current_user.role != UserRole.ADMIN:
    flash("No tienes permisos...", "danger")
    return redirect(url_for('index'))
```

### Authorization Checks

All sensitive routes include role verification:
- Admin-only routes: user management, candidate registration, audit logs
- Student-only routes: voting
- Authenticated routes: profile management, password changes

---

## Password Security

### Password Hashing

**Library:** Werkzeug Security

**Implementation:**
```python
from werkzeug.security import generate_password_hash, check_password_hash

def set_password(self, password):
    self.password_hash = generate_password_hash(password)

def check_password(self, password):
    return check_password_hash(self.password_hash, password)
```

**Features:**
- Passwords never stored in plain text
- Industry-standard hashing algorithm (PBKDF2-SHA256)
- Automatic salt generation
- One-way hashing (cannot be reversed)

### Password Requirements

**Current Requirements:**
- Minimum length: 6 characters (configurable in forms.py)

**Recommendations for Production:**
- Increase minimum to 12 characters
- Require uppercase, lowercase, numbers, special characters
- Implement password strength meter
- Check against common password lists
- Enforce password expiration

### Password Change Logging

All password changes are logged:
```python
log = PasswordChangeLog(
    changed_by_user_id=current_user.id,
    affected_user_id=target_user.id
)
db.session.add(log)
```

**Security Benefits:**
- Audit trail of all password modifications
- Detects unauthorized changes
- Tracks admin vs. self-changes
- Exportable for compliance reporting

---

## CSRF Protection

### Flask-WTF CSRF

**Implementation:**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

**Protection Features:**
- Automatic CSRF token generation for all forms
- Token validation on all POST requests
- Tokens tied to user session
- Time-limited tokens

### CSRF Token Usage

**In Forms:**
```python
class LoginForm(FlaskForm):
    # CSRF token automatically included
    username = StringField('Usuario', validators=[DataRequired()])
```

**In Templates:**
```html
<form method="POST">
    {{ form.hidden_tag() }}  <!-- Includes CSRF token -->
    {{ form.username }}
    {{ form.password }}
    {{ form.submit }}
</form>
```

**Token Verification:**
- Automatic on all Flask-WTF form submissions
- Fails with 400 Bad Request on invalid token
- Prevents cross-site request forgery attacks

---

## Input Validation

### WTForms Validators

All user input validated using WTForms:

**Common Validators:**
```python
from wtforms.validators import DataRequired, Length, Email

# Username validation
username = StringField('Usuario', validators=[
    DataRequired(),
    Length(min=4, max=50)
])

# Password validation
password = PasswordField('Contraseña', validators=[
    DataRequired(),
    Length(min=6)
])

# Email validation
email = StringField('Email', validators=[
    DataRequired(),
    Length(min=4, max=50)
])
```

### Server-Side Validation

**All validation occurs server-side:**
- Client-side validation can be bypassed
- Server always validates before processing
- Database constraints as additional layer

### File Upload Validation

**Allowed Extensions:**
```python
profile_picture = FileField('Imagen de perfil', validators=[
    FileAllowed(['jpg', 'png', 'jpeg', 'webp'], '¡Solo imágenes!')
])
```

**Additional Checks:**
- Secure filename generation
- File size limits (configurable)
- MIME type verification recommended for production

---

## Session Management

### Session Configuration

**Configuration in `config.py`:**
```python
SECRET_KEY = os.getenv('SECRET_KEY', 'una_clave_secreta_segura')
```

**Security Features:**
- Session cookies are httpOnly (prevents XSS access)
- Secure flag in production (HTTPS only)
- Session data server-side (not in cookie)
- Automatic session expiration

### Session Security Recommendations

**For Production:**
1. Set `SESSION_COOKIE_SECURE = True` (HTTPS only)
2. Set `SESSION_COOKIE_HTTPONLY = True` (already enabled)
3. Set `SESSION_COOKIE_SAMESITE = 'Lax'` (CSRF protection)
4. Configure `PERMANENT_SESSION_LIFETIME` (e.g., 30 minutes)
5. Use strong, random SECRET_KEY from environment

**Example Production Config:**
```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
```

---

## Rate Limiting & Account Lockout

### Failed Login Tracking

**Implementation:**
```python
MAX_ATTEMPTS = 3
BLOCK_TIME = 15  # seconds

class FailedLoginAttempt(db.Model):
    username = db.Column(db.String(50), unique=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.Integer, default=0)
```

### Lockout Logic

**Process:**
1. Track failed attempts per username
2. Increment counter on failed login
3. Reset counter on successful login
4. Block login if attempts >= MAX_ATTEMPTS
5. Auto-unlock after BLOCK_TIME seconds

**Code:**
```python
if failed_attempt.attempts >= MAX_ATTEMPTS:
    time_since_last = current_time - failed_attempt.last_attempt
    if time_since_last < BLOCK_TIME:
        remaining = BLOCK_TIME - time_since_last
        flash(f"Demasiados intentos. Inténtalo en {remaining}s", "danger")
        return redirect(url_for('login'))
```

### Brute Force Protection

**Current Protection:**
- Per-username rate limiting
- Time-based lockout
- reCAPTCHA on every login

**Recommendations for Production:**
- Increase BLOCK_TIME (e.g., 5-15 minutes)
- Implement exponential backoff
- Add IP-based rate limiting
- Log suspicious activity
- Email alerts on multiple failures

---

## Audit Logging

### Username Change Logs

**Model:**
```python
class UsernameChangeLog(db.Model):
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    old_username = db.Column(db.String(20))
    new_username = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

**What's Logged:**
- Who made the change (admin or self)
- Which user was affected
- Old and new usernames
- Exact timestamp

### Password Change Logs

**Model:**
```python
class PasswordChangeLog(db.Model):
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

**What's Logged:**
- Who made the change
- Which user was affected
- Timestamp
- **Note:** Passwords themselves are NEVER logged

### Log Export Features

**Available Formats:**
- Excel (.xlsx) - for data analysis
- PDF (.pdf) - for formal reports

**Access Control:**
- Only ADMIN role can view/export logs
- Logs are immutable (insert-only)

### Compliance Benefits

Audit logs support:
- Security incident investigation
- Compliance requirements (GDPR, etc.)
- Accountability and transparency
- Detecting unauthorized changes

---

## File Upload Security

### Allowed File Types

**Profile Pictures:**
- jpg, jpeg, png, webp

**Candidate Photos:**
- jpg, jpeg, png

### Secure Filename Handling

**Implementation:**
```python
from werkzeug.utils import secure_filename

filename = secure_filename(file.filename)
```

**Security Benefits:**
- Prevents directory traversal attacks (../)
- Removes special characters
- Ensures filename is safe for filesystem

### File Storage

**Profile Photos:**
- Stored in: `uploads/photos/`
- Unique filenames prevent overwriting

**Candidate Photos:**
- Stored in: `static/candidate_photos/`
- Format: `{name}_{lastname}_{timestamp}.{ext}`

### Recommendations for Production

1. **File Size Limits:**
   ```python
   app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
   ```

2. **MIME Type Validation:**
   ```python
   import imghdr

   def validate_image(stream):
       header = stream.read(512)
       stream.seek(0)
       format = imghdr.what(None, header)
       if not format:
           return None
       return '.' + format in ALLOWED_EXTENSIONS
   ```

3. **Antivirus Scanning:**
   - Scan uploads with ClamAV or similar
   - Quarantine suspicious files

4. **Storage Outside Web Root:**
   - Store uploads outside public directory
   - Serve via dedicated route with access control

---

## Database Security

### SQL Injection Prevention

**SQLAlchemy ORM:**
- All queries use SQLAlchemy ORM
- Automatic parameter escaping
- No raw SQL queries with user input

**Safe Query Example:**
```python
# Safe - uses ORM
user = User.query.filter_by(username=username).first()

# Unsafe - DON'T DO THIS
# user = db.session.execute(f"SELECT * FROM user WHERE username='{username}'")
```

### Database Constraints

**Unique Constraints:**
```python
__table_args__ = (
    db.UniqueConstraint('username', 'role', name='uq_username_role'),
)
```

**Foreign Key Constraints:**
```python
user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
```

**Cascading Deletes:**
```python
profile = db.relationship(
    'UserProfile',
    cascade="all, delete-orphan"
)
```

### Database Connection Security

**Current Configuration:**
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/college_student_election'
```

**Production Recommendations:**
1. Use strong database password
2. Create dedicated database user with minimal permissions
3. Use environment variables for credentials
4. Enable SSL/TLS for database connections
5. Restrict database access by IP

**Example Production Config:**
```python
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME')

SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?ssl=true'
```

---

## reCAPTCHA Integration

### Implementation

**Server-Side Verification:**
```python
RECAPTCHA_SECRET_KEY = '6LfzLRsrAAAAALyqQGFcF0LFAHBPavE_lqE0yAhD'

recaptcha_response = request.form.get('g-recaptcha-response')
payload = {
    'secret': RECAPTCHA_SECRET_KEY,
    'response': recaptcha_response
}
r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
result = r.json()

if not result.get('success'):
    flash('reCAPTCHA falló. Inténtalo de nuevo.', 'danger')
```

### Security Benefits

- Prevents automated bot attacks
- Reduces brute force attempts
- Protects against credential stuffing
- Free for moderate traffic

### Configuration

**Important:** Update the reCAPTCHA keys for production:
1. Get new keys from https://www.google.com/recaptcha/admin
2. Update `RECAPTCHA_SECRET_KEY` in app.py
3. Update site key in templates/login.html
4. Use environment variables for keys

---

## Security Best Practices

### Environment Variables

**Current Issues:**
- SECRET_KEY has default value
- Database credentials in code
- reCAPTCHA keys hardcoded

**Recommended Approach:**
```python
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
DATABASE_URI = os.getenv('DATABASE_URI')
```

**.env file (never commit to git):**
```
SECRET_KEY=your-very-long-random-secret-key-here
RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
DATABASE_URI=mysql+pymysql://user:pass@localhost/db
```

### HTTPS Enforcement

**For Production:**
```python
from flask_talisman import Talisman

Talisman(app, force_https=True)
```

**Benefits:**
- Encrypts all traffic
- Prevents man-in-the-middle attacks
- Required for secure cookies
- SEO benefits

### Security Headers

**Recommended Headers:**
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### Debug Mode

**CRITICAL:** Never run in debug mode in production!

```python
# Development
app.run(debug=True)

# Production
app.run(debug=False)
```

**Why:**
- Debug mode exposes sensitive information
- Shows source code in error pages
- Allows code execution via debugger

---

## Known Limitations

### Current Security Gaps

1. **Weak Password Policy**
   - Only 6 character minimum
   - No complexity requirements

2. **No Email Verification**
   - Email addresses not verified
   - Could lead to fake accounts

3. **No Two-Factor Authentication**
   - Single factor authentication only
   - Vulnerable to password compromise

4. **Limited Rate Limiting**
   - Only on login attempts
   - No rate limiting on other routes

5. **No Account Recovery**
   - No password reset mechanism
   - Requires admin intervention

6. **File Upload Risks**
   - Only extension-based validation
   - No MIME type verification
   - No antivirus scanning

7. **Session Fixation**
   - Session ID not regenerated on login
   - Potential session fixation vulnerability

### Planned Improvements

- Implement email verification
- Add 2FA support (TOTP)
- Strengthen password requirements
- Add password reset workflow
- Implement global rate limiting
- Add MIME type validation
- Session regeneration on login

---

## Security Checklist for Deployment

### Pre-Production Checklist

- [ ] Change SECRET_KEY to strong random value
- [ ] Move all secrets to environment variables
- [ ] Update reCAPTCHA keys
- [ ] Change default admin password
- [ ] Set `DEBUG = False`
- [ ] Enable HTTPS/SSL
- [ ] Configure secure session cookies
- [ ] Set up database with strong password
- [ ] Create dedicated database user with minimal permissions
- [ ] Enable database SSL connections
- [ ] Implement security headers
- [ ] Set up file size limits
- [ ] Configure proper file permissions
- [ ] Enable logging to file
- [ ] Set up monitoring/alerting
- [ ] Conduct security audit
- [ ] Perform penetration testing
- [ ] Review and update dependencies
- [ ] Set up automated backups
- [ ] Document incident response plan

### Ongoing Security Maintenance

- [ ] Regularly update dependencies
- [ ] Monitor security advisories
- [ ] Review audit logs weekly
- [ ] Test backup restoration
- [ ] Rotate secrets periodically
- [ ] Conduct security reviews
- [ ] Update security documentation
- [ ] Train users on security best practices

---

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this system:

1. **Do NOT** open a public issue
2. Email security details to [security contact]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. Allow reasonable time for fix before disclosure

---

## Security Resources

### References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [SQLAlchemy Security](https://docs.sqlalchemy.org/en/latest/faq/security.html)

### Tools
- [OWASP ZAP](https://www.zaproxy.org/) - Web security scanner
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [Safety](https://pyup.io/safety/) - Dependency vulnerability checker

---

**Last Updated:** 2025

**Version:** 1.0

**Maintained by:** λ-SanchoDev
