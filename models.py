from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from datetime import datetime
import enum


db = SQLAlchemy()

class UserRole(enum.Enum):
    """
    Enumeration of user roles in the system.

    Attributes:
        ADMIN: Administrator with full system access
        ESTUDIANTE: Student who can vote
        DOCENTE: Teacher with limited access
    """
    ADMIN = "admin"
    ESTUDIANTE = "estudiante"
    DOCENTE = "docente"

class User(db.Model, UserMixin):
    """
    User model for authentication and authorization.

    Attributes:
        id: Primary key
        username: Unique username (max 50 chars)
        password_hash: Hashed password using Werkzeug
        role: UserRole enum (ADMIN, ESTUDIANTE, DOCENTE)
        profile: One-to-one relationship with UserProfile

    Constraints:
        - Unique constraint on (username, role) combination
        - Username must be unique across roles
        - Cascading delete: deleting user also deletes profile

    Methods:
        set_password(password): Hash and store password
        check_password(password): Verify password against hash
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.ESTUDIANTE, nullable=False)

    profile = db.relationship(
        'UserProfile',
        uselist=False,
        back_populates='user',
        cascade="all, delete-orphan",
        primaryjoin="User.username == UserProfile.user_name"
    )

    def set_password(self, password):
        """Hash and store the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against stored hash."""
        return check_password_hash(self.password_hash, password)

    __table_args__ = (
    db.UniqueConstraint('username', 'role', name='uq_username_role'),
)   

class Candidate(db.Model):
    """
    Election candidate model.

    Attributes:
        id: Primary key
        name: Candidate's first name (max 50 chars)
        last_name: Candidate's last name (max 50 chars)
        propuesta: Campaign proposal (max 500 chars)
        profile_picture: Optional filename of candidate's photo

    Relationships:
        votes: One-to-many relationship with Vote model
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    propuesta = db.Column(db.String(500), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)

class FailedLoginAttempt(db.Model):
    """
    Track failed login attempts for security.

    Used to implement account lockout after multiple failed login attempts.

    Attributes:
        id: Primary key
        username: Username being tracked (unique)
        attempts: Number of failed login attempts
        last_attempt: Unix timestamp of last failed attempt

    Security:
        After MAX_ATTEMPTS (3) failures, account is locked for BLOCK_TIME (15s)
        Counter resets on successful login or after block time expires
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.Integer, default=0)

class Vote(db.Model):
    """
    Model representing a vote cast by a user for a candidate.

    Attributes:
        id: Primary key
        user_id: Foreign key to User table
        candidate_id: Foreign key to Candidate table
        timestamp: When the vote was cast (auto-set to UTC now)

    Constraints:
        - Unique constraint on user_id (one vote per user)
        - Prevents duplicate voting

    Relationships:
        user: Many-to-one with User (single vote per user)
        candidate: Many-to-one with Candidate (many votes per candidate)
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', name='one_vote_per_user'),)

    user = db.relationship('User', backref=db.backref('vote', lazy=True, uselist=False))
    candidate = db.relationship('Candidate', backref=db.backref('votes', lazy=True))

class UserProfile(db.Model):
    """
    Extended user profile information.

    Attributes:
        id: Primary key
        user_name: Foreign key to User.username (cascading updates/deletes)
        user_id: Foreign key to User.id
        email: User's email address (unique, optional)
        name: User's first name (optional)
        last_name: User's last name (optional)
        profile_picture: Filename of profile picture (optional)

    Relationships:
        user: One-to-one relationship with User model

    Constraints:
        - user_name must be unique
        - email must be unique if provided
        - Cascading updates and deletes with User table
    """
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(
        db.String(20),
        db.ForeignKey('user.username', onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
        unique=True
    )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(50),unique=True, nullable=True)
    name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    user = db.relationship(
        'User',
        back_populates='profile',
        foreign_keys=[user_name],
        primaryjoin="UserProfile.user_name == User.username"
    )

    def __repr__(self):
        return f"<UserProfile {self.user.username}>"

class UsernameChangeLog(db.Model):
    """
    Audit log for username changes.

    Tracks all username modifications for security and accountability.

    Attributes:
        id: Primary key
        changed_by_user_id: ID of user who made the change (admin or self)
        affected_user_id: ID of user whose username was changed
        old_username: Previous username
        new_username: New username
        timestamp: When the change occurred (auto-set to UTC now)

    Relationships:
        changed_by: User who performed the change
        affected_user: User whose username was changed

    Security:
        - Immutable log (no updates, only inserts)
        - Tracks both self-changes and admin changes
        - Exportable to PDF/Excel for audit reports
    """
    id = db.Column(db.Integer, primary_key=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    old_username = db.Column(db.String(20), nullable=False)
    new_username = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    changed_by = db.relationship('User', foreign_keys=[changed_by_user_id], backref='changes_made')
    affected_user = db.relationship('User', foreign_keys=[affected_user_id], backref='changes_received')

    def __repr__(self):
        return f"<Log {self.timestamp} | {self.changed_by.username} cambió {self.old_username} → {self.new_username}>"

class PasswordChangeLog(db.Model):
    """
    Audit log for password changes.

    Tracks all password modifications for security and accountability.
    Does not store old or new passwords (only fact that change occurred).

    Attributes:
        id: Primary key
        changed_by_user_id: ID of user who made the change (admin or self)
        affected_user_id: ID of user whose password was changed
        timestamp: When the change occurred (auto-set to UTC now)

    Relationships:
        changed_by: User who performed the change
        affected_user: User whose password was changed

    Security:
        - Immutable log (no updates, only inserts)
        - Does NOT store password values (only metadata)
        - Tracks both self-changes and admin changes
        - Exportable to PDF/Excel for audit reports
    """
    id = db.Column(db.Integer, primary_key=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    changed_by = db.relationship('User', foreign_keys=[changed_by_user_id], backref='password_changes_made')
    affected_user = db.relationship('User', foreign_keys=[affected_user_id], backref='password_changes_received')

    def __repr__(self):
        return f"<PasswordLog {self.timestamp} | {self.changed_by.username} cambió la contraseña de {self.affected_user.username}>"