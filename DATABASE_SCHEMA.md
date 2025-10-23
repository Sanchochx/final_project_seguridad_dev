# Database Schema Documentation

This document provides comprehensive documentation of the database schema for the College Student Election System.

## Table of Contents
- [Overview](#overview)
- [Entity Relationship Diagram](#entity-relationship-diagram)
- [Tables](#tables)
- [Relationships](#relationships)
- [Indexes and Constraints](#indexes-and-constraints)
- [Database Setup](#database-setup)
- [Data Flow](#data-flow)

---

## Overview

**Database Management System:** MySQL
**ORM:** SQLAlchemy
**Connection:** PyMySQL driver
**Database Name:** `college_student_election`

### Key Features
- Automatic schema creation via SQLAlchemy
- Foreign key constraints for referential integrity
- Cascading updates and deletes
- Unique constraints for data integrity
- Audit logging for critical operations

---

## Entity Relationship Diagram

```
┌─────────────────┐
│      User       │
│─────────────────│
│ id (PK)         │
│ username        │───┐
│ password_hash   │   │
│ role            │   │
└─────────────────┘   │
         │            │
         │ 1:1        │ FK
         │            │
         ▼            ▼
┌─────────────────┐ ┌──────────────────┐
│  UserProfile    │ │ FailedLoginAttempt│
│─────────────────│ │──────────────────│
│ id (PK)         │ │ id (PK)          │
│ user_name (FK)  │ │ username         │
│ user_id (FK)    │ │ attempts         │
│ email           │ │ last_attempt     │
│ name            │ └──────────────────┘
│ last_name       │
│ profile_picture │
└─────────────────┘

┌─────────────────┐         ┌─────────────────┐
│   Candidate     │         │      Vote       │
│─────────────────│         │─────────────────│
│ id (PK)         │◄────────│ id (PK)         │
│ name            │    1:N  │ user_id (FK)    │
│ last_name       │         │ candidate_id(FK)│
│ propuesta       │         │ timestamp       │
│ profile_picture │         └─────────────────┘
└─────────────────┘                 │
                                    │ N:1
                                    │
                            ┌───────▼────────┐
                            │      User      │
                            │ (shown above)  │
                            └────────────────┘

┌─────────────────────────┐        ┌──────────────────────┐
│  UsernameChangeLog      │        │ PasswordChangeLog    │
│─────────────────────────│        │──────────────────────│
│ id (PK)                 │        │ id (PK)              │
│ changed_by_user_id (FK) │        │ changed_by_user_id(FK)│
│ affected_user_id (FK)   │        │ affected_user_id (FK)│
│ old_username            │        │ timestamp            │
│ new_username            │        └──────────────────────┘
│ timestamp               │                 │
└─────────────────────────┘                 │
         │                                  │
         │ N:1                              │ N:1
         └──────────────┬───────────────────┘
                        │
                        ▼
                ┌───────────────┐
                │     User      │
                │ (shown above) │
                └───────────────┘
```

---

## Tables

### 1. User

**Purpose:** Store user authentication and role information

**Table Name:** `user`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique user identifier |
| `username` | VARCHAR(50) | NOT NULL, UNIQUE | User's login name |
| `password_hash` | VARCHAR(255) | NOT NULL | Hashed password (Werkzeug) |
| `role` | ENUM | NOT NULL, DEFAULT 'estudiante' | User role (admin/docente/estudiante) |

**Constraints:**
```sql
PRIMARY KEY (id)
UNIQUE (username, role)  -- Named: uq_username_role
```

**Indexes:**
- Primary key index on `id`
- Unique index on `username`
- Index on `role` (for filtering)

**Model Definition:**
```python
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.ESTUDIANTE, nullable=False)
```

---

### 2. UserProfile

**Purpose:** Extended user information (profile details)

**Table Name:** `user_profile`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Profile ID |
| `user_name` | VARCHAR(20) | FOREIGN KEY, NOT NULL, UNIQUE | References user.username |
| `user_id` | INTEGER | FOREIGN KEY, NOT NULL | References user.id |
| `email` | VARCHAR(50) | UNIQUE, NULLABLE | User's email address |
| `name` | VARCHAR(50) | NULLABLE | User's first name |
| `last_name` | VARCHAR(50) | NULLABLE | User's last name |
| `profile_picture` | VARCHAR(255) | NULLABLE | Filename of profile photo |

**Constraints:**
```sql
PRIMARY KEY (id)
FOREIGN KEY (user_name) REFERENCES user(username) ON UPDATE CASCADE ON DELETE CASCADE
FOREIGN KEY (user_id) REFERENCES user(id)
UNIQUE (user_name)
UNIQUE (email)
```

**Relationships:**
- One-to-one with User (via `user_name`)
- Cascading updates and deletes

**Model Definition:**
```python
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20),
        db.ForeignKey('user.username', onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=True)
    name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
```

---

### 3. Candidate

**Purpose:** Store election candidate information

**Table Name:** `candidate`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Candidate ID |
| `name` | VARCHAR(50) | NOT NULL | Candidate's first name |
| `last_name` | VARCHAR(50) | NOT NULL | Candidate's last name |
| `propuesta` | VARCHAR(500) | NOT NULL | Campaign proposal/platform |
| `profile_picture` | VARCHAR(255) | NULLABLE | Filename of candidate photo |

**Model Definition:**
```python
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    propuesta = db.Column(db.String(500), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)
```

---

### 4. Vote

**Purpose:** Record votes cast by users for candidates

**Table Name:** `vote`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Vote ID |
| `user_id` | INTEGER | FOREIGN KEY, NOT NULL, UNIQUE | References user.id |
| `candidate_id` | INTEGER | FOREIGN KEY, NOT NULL | References candidate.id |
| `timestamp` | DATETIME | NOT NULL, DEFAULT UTC_NOW | When vote was cast |

**Constraints:**
```sql
PRIMARY KEY (id)
FOREIGN KEY (user_id) REFERENCES user(id)
FOREIGN KEY (candidate_id) REFERENCES candidate(id)
UNIQUE (user_id)  -- Named: one_vote_per_user
```

**Security Features:**
- One vote per user enforced by unique constraint
- Timestamp for audit trail
- Vote cannot be changed (no update logic)

**Model Definition:**
```python
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', name='one_vote_per_user'),)
```

---

### 5. FailedLoginAttempt

**Purpose:** Track failed login attempts for security

**Table Name:** `failed_login_attempt`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Record ID |
| `username` | VARCHAR(50) | NOT NULL, UNIQUE | Username being tracked |
| `attempts` | INTEGER | NOT NULL, DEFAULT 0 | Number of failed attempts |
| `last_attempt` | INTEGER | NOT NULL, DEFAULT 0 | Unix timestamp of last attempt |

**Usage:**
- Tracks failed login attempts per username
- Implements rate limiting (max 3 attempts)
- Auto-lockout for 15 seconds after max attempts
- Counter resets on successful login

**Model Definition:**
```python
class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.Integer, default=0)
```

---

### 6. UsernameChangeLog

**Purpose:** Audit log for username modifications

**Table Name:** `username_change_log`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Log entry ID |
| `changed_by_user_id` | INTEGER | FOREIGN KEY, NOT NULL | User who made the change |
| `affected_user_id` | INTEGER | FOREIGN KEY, NOT NULL | User whose username was changed |
| `old_username` | VARCHAR(20) | NOT NULL | Previous username |
| `new_username` | VARCHAR(20) | NOT NULL | New username |
| `timestamp` | DATETIME | NOT NULL, DEFAULT UTC_NOW | When change occurred |

**Constraints:**
```sql
PRIMARY KEY (id)
FOREIGN KEY (changed_by_user_id) REFERENCES user(id)
FOREIGN KEY (affected_user_id) REFERENCES user(id)
```

**Usage:**
- Immutable audit trail (insert-only)
- Tracks self-changes and admin changes
- Exportable to PDF/Excel

**Model Definition:**
```python
class UsernameChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    old_username = db.Column(db.String(20), nullable=False)
    new_username = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

---

### 7. PasswordChangeLog

**Purpose:** Audit log for password modifications

**Table Name:** `password_change_log`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Log entry ID |
| `changed_by_user_id` | INTEGER | FOREIGN KEY, NOT NULL | User who made the change |
| `affected_user_id` | INTEGER | FOREIGN KEY, NOT NULL | User whose password was changed |
| `timestamp` | DATETIME | NOT NULL, DEFAULT UTC_NOW | When change occurred |

**Constraints:**
```sql
PRIMARY KEY (id)
FOREIGN KEY (changed_by_user_id) REFERENCES user(id)
FOREIGN KEY (affected_user_id) REFERENCES user(id)
```

**Security Notes:**
- Does NOT store passwords (old or new)
- Only logs metadata about the change
- Tracks who made the change and when

**Model Definition:**
```python
class PasswordChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    affected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## Relationships

### User ↔ UserProfile (One-to-One)

**Definition:**
```python
# In User model
profile = db.relationship('UserProfile', uselist=False,
    back_populates='user', cascade="all, delete-orphan")

# In UserProfile model
user = db.relationship('User', back_populates='profile',
    foreign_keys=[user_name])
```

**Behavior:**
- Each user has exactly one profile
- Deleting user deletes profile (cascade)
- Updating username updates profile.user_name (cascade)

---

### User ↔ Vote (One-to-Many, but constrained to One-to-One)

**Definition:**
```python
# In Vote model
user = db.relationship('User', backref=db.backref('vote', lazy=True, uselist=False))
```

**Behavior:**
- One user can have at most one vote (enforced by unique constraint)
- `uselist=False` indicates one-to-one relationship
- Vote cannot be deleted by user (no cascade delete)

---

### Candidate ↔ Vote (One-to-Many)

**Definition:**
```python
# In Vote model
candidate = db.relationship('Candidate', backref=db.backref('votes', lazy=True))
```

**Behavior:**
- One candidate can have many votes
- Deleting candidate would violate foreign key (protect votes)
- Used for aggregating vote counts

---

### User ↔ Audit Logs (One-to-Many)

**UsernameChangeLog:**
```python
changed_by = db.relationship('User', foreign_keys=[changed_by_user_id],
    backref='changes_made')
affected_user = db.relationship('User', foreign_keys=[affected_user_id],
    backref='changes_received')
```

**PasswordChangeLog:**
```python
changed_by = db.relationship('User', foreign_keys=[changed_by_user_id],
    backref='password_changes_made')
affected_user = db.relationship('User', foreign_keys=[affected_user_id],
    backref='password_changes_received')
```

**Behavior:**
- Two relationships per log entry (who changed, who was affected)
- Separate backrefs to avoid naming conflicts
- Foreign keys prevent deletion of users with log entries

---

## Indexes and Constraints

### Primary Keys
Every table has an auto-incrementing integer primary key named `id`.

### Unique Constraints

| Table | Column(s) | Name | Purpose |
|-------|-----------|------|---------|
| User | username, role | uq_username_role | Prevent duplicate usernames per role |
| UserProfile | user_name | - | One profile per user |
| UserProfile | email | - | Unique email addresses |
| Vote | user_id | one_vote_per_user | One vote per user |
| FailedLoginAttempt | username | - | Track per username |

### Foreign Key Constraints

| From Table | Column | References | On Delete | On Update |
|------------|--------|------------|-----------|-----------|
| UserProfile | user_name | user.username | CASCADE | CASCADE |
| UserProfile | user_id | user.id | RESTRICT | RESTRICT |
| Vote | user_id | user.id | RESTRICT | RESTRICT |
| Vote | candidate_id | candidate.id | RESTRICT | RESTRICT |
| UsernameChangeLog | changed_by_user_id | user.id | RESTRICT | RESTRICT |
| UsernameChangeLog | affected_user_id | user.id | RESTRICT | RESTRICT |
| PasswordChangeLog | changed_by_user_id | user.id | RESTRICT | RESTRICT |
| PasswordChangeLog | affected_user_id | user.id | RESTRICT | RESTRICT |

### Indexes

**Automatically Created:**
- Primary key indexes (all tables)
- Unique constraint indexes (username, email, etc.)
- Foreign key indexes (for join performance)

**Recommended Additional Indexes:**
```sql
CREATE INDEX idx_vote_timestamp ON vote(timestamp);
CREATE INDEX idx_username_log_timestamp ON username_change_log(timestamp);
CREATE INDEX idx_password_log_timestamp ON password_change_log(timestamp);
```

---

## Database Setup

### Initial Setup

**Step 1: Create Database**
```sql
CREATE DATABASE college_student_election
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
```

**Step 2: Create Tables (Automatic)**
```python
# In app.py
with app.app_context():
    db.create_all()
```

**Step 3: Create Initial Admin**
```bash
python create_admin.py
```

### Database Migrations

**For Schema Changes:**
```bash
# Install Flask-Migrate
pip install Flask-Migrate

# Initialize migrations
flask db init

# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade
```

---

## Data Flow

### User Registration Flow

```
1. Admin accesses /register/<role>
2. Fills RegisterForm with username/password
3. System creates User record
4. System creates associated UserProfile record
5. Both records committed in single transaction
6. User can now login
```

### Voting Flow

```
1. Student logs in
2. Navigates to /vote
3. System checks:
   - User role is ESTUDIANTE
   - User has not voted yet (query Vote table)
4. Student selects candidate
5. System creates Vote record with:
   - user_id (from current_user)
   - candidate_id (from form)
   - timestamp (auto-generated)
6. Unique constraint prevents duplicate voting
7. Redirect to /results
```

### Username Change Flow

```
1. User or Admin accesses edit username form
2. Submits new username
3. System validates:
   - New username is unique within role
   - User has permission to make change
4. Transaction begins:
   - Update User.username
   - Update UserProfile.user_name (cascades automatically)
   - Create UsernameChangeLog entry
5. Transaction commits or rolls back on error
6. Audit log now shows the change
```

### Results Aggregation

```sql
-- Query used in /results route
SELECT
    candidate.*,
    COUNT(vote.id) as vote_count
FROM candidate
LEFT JOIN vote ON candidate.id = vote.candidate_id
GROUP BY candidate.id
ORDER BY vote_count DESC;
```

---

## Backup and Recovery

### Backup Strategy

**Daily Backups:**
```bash
mysqldump -u root -p college_student_election > backup_$(date +%Y%m%d).sql
```

**Backup Tables Individually:**
```bash
mysqldump -u root -p college_student_election user > user_backup.sql
mysqldump -u root -p college_student_election vote > vote_backup.sql
```

### Recovery

**Full Database Restore:**
```bash
mysql -u root -p college_student_election < backup_20250101.sql
```

**Table Restore:**
```bash
mysql -u root -p college_student_election < user_backup.sql
```

---

## Performance Considerations

### Query Optimization

**Indexed Queries:**
- User lookup by username: O(log n) via index
- Vote count by candidate: Uses GROUP BY with index

**N+1 Query Prevention:**
```python
# Use eager loading for relationships
users = User.query.options(joinedload(User.profile)).all()
```

### Connection Pooling

**Configure in production:**
```python
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
```

---

## Schema Version

**Version:** 1.0
**Last Updated:** 2025
**Maintained by:** λ-SanchoDev

---

## Future Schema Enhancements

Planned additions:
1. Election table (support multiple elections)
2. EmailVerification table (email confirmation tokens)
3. TwoFactorAuth table (TOTP secrets)
4. PasswordReset table (reset tokens)
5. Activity log table (all user actions)
6. Notifications table (user notifications)
