# Contributing Guidelines

Thank you for your interest in contributing to the College Student Election System! This document provides guidelines and best practices for contributing to this project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [Git Workflow](#git-workflow)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

---

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility for mistakes

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Any conduct inappropriate in a professional setting

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:
- Python 3.8 or higher
- MySQL Server
- Git
- Text editor or IDE (VS Code, PyCharm, etc.)
- Basic understanding of Flask and SQLAlchemy

### Initial Setup

1. **Fork the Repository**
   ```bash
   # Click "Fork" on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/final_project_seguridad_dev.git
   cd final_project_seguridad_dev
   ```

2. **Set Up Upstream Remote**
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/final_project_seguridad_dev.git
   ```

3. **Create Virtual Environment**
   ```bash
   python -m venv venv

   # Windows
   venv\Scripts\activate

   # Linux/Mac
   source venv/bin/activate
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set Up Database**
   ```sql
   CREATE DATABASE college_student_election_dev;
   ```

6. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your local settings
   ```

7. **Initialize Database**
   ```bash
   python create_admin.py
   ```

8. **Run Application**
   ```bash
   python app.py
   ```

---

## Development Environment

### Recommended Tools

**IDE/Editors:**
- Visual Studio Code with Python extension
- PyCharm Professional or Community
- Sublime Text with Python plugins

**VS Code Extensions:**
- Python (Microsoft)
- Pylance
- SQLTools
- GitLens

### Environment Variables

Create `.env` file with:
```
SECRET_KEY=your-development-secret-key
DATABASE_URI=mysql+pymysql://root:password@localhost/college_student_election_dev
RECAPTCHA_SECRET_KEY=your-recaptcha-key
DEBUG=True
```

**Never commit `.env` to Git!**

---

## Coding Standards

### Python Style Guide

Follow [PEP 8](https://pep8.org/) guidelines:

**Formatting:**
```python
# Good
def calculate_total_votes(candidate_id):
    """Calculate total votes for a candidate."""
    votes = Vote.query.filter_by(candidate_id=candidate_id).count()
    return votes

# Bad
def CalculateTotalVotes(candidateId):
    votes=Vote.query.filter_by(candidate_id=candidateId).count()
    return votes
```

**Naming Conventions:**
- Functions/variables: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_CASE`
- Private methods: `_leading_underscore`

**Imports:**
```python
# Standard library
import os
import time
from datetime import datetime

# Third-party
from flask import Flask, render_template
from sqlalchemy import func

# Local
from models import User, Vote
from forms import LoginForm
```

### Docstrings

All functions, classes, and modules must have docstrings:

```python
def register_user(username, password, role):
    """
    Register a new user in the system.

    Args:
        username (str): Unique username (4-50 chars)
        password (str): Plain text password (will be hashed)
        role (UserRole): User role enum value

    Returns:
        User: The newly created user object

    Raises:
        ValueError: If username already exists
        ValueError: If password is too short

    Example:
        >>> user = register_user("john_doe", "secure123", UserRole.ESTUDIANTE)
        >>> print(user.username)
        john_doe
    """
    # Implementation
```

### Code Comments

Write clear, concise comments:

```python
# Good - explains WHY
# Use Unix timestamp for compatibility with JavaScript
last_attempt = int(time.time())

# Bad - explains WHAT (obvious from code)
# Set last_attempt to current time
last_attempt = int(time.time())
```

### Error Handling

Always handle errors gracefully:

```python
try:
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash("Usuario registrado con éxito", "success")
except IntegrityError:
    db.session.rollback()
    flash("El usuario ya existe", "danger")
except Exception as e:
    db.session.rollback()
    app.logger.error(f"Error registering user: {str(e)}")
    flash("Error al registrar usuario", "danger")
```

### Security Guidelines

**Always:**
- Validate all user input
- Use parameterized queries (SQLAlchemy ORM)
- Hash passwords before storage
- Implement CSRF protection
- Sanitize file uploads
- Log security events

**Never:**
- Store passwords in plain text
- Trust user input without validation
- Use string formatting for SQL queries
- Expose sensitive data in error messages
- Commit secrets to Git

---

## Git Workflow

### Branching Strategy

**Main Branches:**
- `main`: Production-ready code
- `develop`: Integration branch for features

**Feature Branches:**
- `feature/description`: New features
- `bugfix/description`: Bug fixes
- `hotfix/description`: Critical production fixes
- `docs/description`: Documentation updates

### Creating a Feature Branch

```bash
# Update develop branch
git checkout develop
git pull upstream develop

# Create feature branch
git checkout -b feature/add-email-verification

# Make changes, then commit
git add .
git commit -m "Add email verification feature"

# Push to your fork
git push origin feature/add-email-verification
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

**Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(auth): add email verification on registration

Implements email verification workflow:
- Send verification email after registration
- Add email_verified column to User model
- Create verification token system

Closes #42

---

fix(vote): prevent duplicate voting

Add unique constraint on Vote.user_id to prevent
users from voting multiple times.

Fixes #58

---

docs(api): update authentication documentation

Add examples for all authentication endpoints
and clarify role-based access control.
```

### Keeping Your Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge into your local develop
git checkout develop
git merge upstream/develop

# Push to your fork
git push origin develop
```

---

## Testing

### Test Structure

```
tests/
├── __init__.py
├── conftest.py          # Pytest fixtures
├── test_auth.py         # Authentication tests
├── test_voting.py       # Voting functionality tests
├── test_admin.py        # Admin functionality tests
└── test_models.py       # Model tests
```

### Writing Tests

**Example Test:**
```python
import pytest
from app import app, db
from models import User, Vote, Candidate

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def test_user_registration(client):
    """Test user registration creates user and profile."""
    response = client.post('/register/estudiante', data={
        'username': 'testuser',
        'password': 'testpass123',
        'csrf_token': 'test'
    })

    assert response.status_code == 302
    user = User.query.filter_by(username='testuser').first()
    assert user is not None
    assert user.profile is not None

def test_duplicate_voting_prevented(client):
    """Test that users cannot vote twice."""
    # Create user and candidate
    user = User(username='voter', role=UserRole.ESTUDIANTE)
    user.set_password('password')
    candidate = Candidate(name='John', last_name='Doe', propuesta='Test')

    db.session.add(user)
    db.session.add(candidate)
    db.session.commit()

    # First vote should succeed
    vote1 = Vote(user_id=user.id, candidate_id=candidate.id)
    db.session.add(vote1)
    db.session.commit()

    # Second vote should fail
    vote2 = Vote(user_id=user.id, candidate_id=candidate.id)
    db.session.add(vote2)

    with pytest.raises(IntegrityError):
        db.session.commit()
```

### Running Tests

```bash
# Install testing dependencies
pip install pytest pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_auth.py

# Run specific test
pytest tests/test_auth.py::test_user_registration
```

### Test Coverage

Aim for at least 80% code coverage:
```bash
pytest --cov=. --cov-report=term-missing
```

---

## Documentation

### Code Documentation

**Required Documentation:**
1. Docstrings for all functions/classes
2. Inline comments for complex logic
3. README updates for new features
4. API documentation updates

### Documentation Standards

**Module Docstring:**
```python
"""
User authentication and authorization module.

This module handles user login, registration, password management,
and role-based access control.

Example:
    from auth import login_user, check_permissions

    if login_user(username, password):
        if check_permissions(user, 'admin'):
            # Admin actions
"""
```

**Function Docstring:**
```python
def calculate_vote_percentage(candidate_id, total_votes):
    """
    Calculate percentage of votes for a candidate.

    Args:
        candidate_id (int): ID of the candidate
        total_votes (int): Total number of votes cast

    Returns:
        float: Percentage rounded to 1 decimal place

    Raises:
        ValueError: If total_votes is zero

    Example:
        >>> calculate_vote_percentage(1, 100)
        25.5
    """
```

### Updating Documentation

When adding features, update:
- `README.md`: User-facing changes
- `API_DOCUMENTATION.md`: New/modified routes
- `DATABASE_SCHEMA.md`: Schema changes
- `SECURITY.md`: Security implications
- Inline code comments
- Docstrings

---

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Commit messages follow convention
- [ ] Branch is up to date with develop

### Submitting a Pull Request

1. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature
   ```

2. **Create Pull Request on GitHub**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Base: `develop`, Compare: `feature/your-feature`
   - Fill out the PR template

3. **PR Template**
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Documentation update
   - [ ] Code refactoring

   ## Testing
   - [ ] Tests pass locally
   - [ ] New tests added

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Documentation updated
   - [ ] No breaking changes
   - [ ] Security implications considered

   ## Related Issues
   Closes #issue_number
   ```

### Review Process

**What Reviewers Look For:**
- Code quality and style
- Test coverage
- Documentation completeness
- Security implications
- Performance impact
- Breaking changes

**Addressing Feedback:**
```bash
# Make requested changes
git add .
git commit -m "Address review feedback"
git push origin feature/your-feature
```

### Merging

- PRs require at least one approval
- All CI checks must pass
- Squash and merge for feature branches
- Merge commit for important features

---

## Security

### Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities!**

Instead:
1. Email security details to [security contact]
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. Wait for response before public disclosure

### Security Checklist

When contributing code:
- [ ] No hardcoded credentials
- [ ] Input validation implemented
- [ ] CSRF tokens on forms
- [ ] XSS prevention (template escaping)
- [ ] SQL injection prevention (ORM)
- [ ] File upload validation
- [ ] Error messages don't leak info
- [ ] Audit logging for sensitive operations

---

## Development Tips

### Common Tasks

**Add a New Route:**
```python
@app.route('/new-route', methods=['GET', 'POST'])
@login_required
def new_route():
    """Docstring explaining route purpose."""
    if current_user.role != UserRole.ADMIN:
        flash("No tienes permisos", "danger")
        return redirect(url_for('index'))

    # Implementation
    return render_template('new_template.html')
```

**Add a New Model:**
```python
class NewModel(db.Model):
    """Model docstring."""
    id = db.Column(db.Integer, primary_key=True)
    # Fields...

# In app.py
with app.app_context():
    db.create_all()
```

**Add a New Form:**
```python
class NewForm(FlaskForm):
    """Form docstring."""
    field = StringField('Label', validators=[DataRequired()])
    submit = SubmitField('Submit')
```

### Debugging

**Enable Debug Mode:**
```python
app.run(debug=True)
```

**Flask Debug Toolbar:**
```bash
pip install flask-debugtoolbar
```

```python
from flask_debugtoolbar import DebugToolbarExtension
toolbar = DebugToolbarExtension(app)
```

**Logging:**
```python
import logging

logging.basicConfig(level=logging.DEBUG)
app.logger.debug("Debug message")
app.logger.error("Error message")
```

---

## Questions?

- Check existing documentation
- Search closed issues
- Open a new issue with "question" label
- Join our [Discord/Slack channel]

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

## Acknowledgments

Thank you to all contributors who help make this project better!

**Maintained by:** λ-SanchoDev

**Last Updated:** 2025
