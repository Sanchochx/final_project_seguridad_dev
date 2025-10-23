# API Documentation - College Student Election System

This document provides comprehensive documentation for all routes and endpoints in the College Student Election System.

## Table of Contents
- [Authentication Routes](#authentication-routes)
- [User Management Routes](#user-management-routes)
- [Candidate Routes](#candidate-routes)
- [Voting Routes](#voting-routes)
- [Profile Management Routes](#profile-management-routes)
- [Audit Log Routes](#audit-log-routes)
- [Export Routes](#export-routes)

## General Notes

### Authentication
- Most routes require authentication via Flask-Login
- Protected routes redirect to login page if user is not authenticated
- Session-based authentication with secure cookies

### Authorization
- **ADMIN**: Full access to all routes
- **ESTUDIANTE**: Can vote, manage own profile, view results
- **DOCENTE**: Can view profile, candidates, and results

### CSRF Protection
- All POST routes are protected with CSRF tokens via Flask-WTF
- CSRF token must be included in all form submissions

---

## Authentication Routes

### Login

**Endpoint:** `POST /login`

**Description:** Authenticate user with username and password

**Access:** Public

**Method:** GET, POST

**Request Body:**
```
username: string (required, 4-50 chars)
password: string (required)
g-recaptcha-response: string (required, reCAPTCHA token)
```

**Security Features:**
- reCAPTCHA verification
- Failed login attempt tracking (max 3 attempts)
- 15-second lockout after max failed attempts
- Password hashing verification

**Response:**
- Success: Redirect to `/index`
- Failure: Flash message and reload login page
- Blocked: Flash message with remaining block time

**Error Handling:**
- Invalid credentials: Flash "Usuario o contraseña incorrectos"
- reCAPTCHA failed: Flash "reCAPTCHA falló. Inténtalo de nuevo."
- Account locked: Flash "Demasiados intentos fallidos. Inténtalo en X segundos."

---

### Logout

**Endpoint:** `GET /logout`

**Description:** Log out the current user

**Access:** Authenticated users only

**Response:** Redirect to `/login` with flash message

---

## User Management Routes

### Register User

**Endpoint:** `POST /register/<role>`

**Description:** Register a new user with specified role (Admin only)

**Access:** ADMIN only

**Method:** GET, POST

**URL Parameters:**
- `role`: string (admin, docente, estudiante)

**Request Body:**
```
username: string (required, 4-50 chars)
password: string (required)
csrf_token: string (required)
```

**Response:**
- Success: Redirect to `/login` with success message
- Failure: Flash error message

**Authorization:**
- Only users with ADMIN role can access
- Non-admin users redirected to `/index`

**Database Operations:**
- Creates new User record
- Creates associated UserProfile record
- Password is hashed before storage

---

### Manage Users

**Endpoint:** `GET /manage_users`

**Description:** Display user management dashboard with search and filter

**Access:** ADMIN only

**Query Parameters:**
- `search`: string (optional, username search)
- `role`: string (optional, role filter: admin/docente/estudiante)

**Response:** Rendered `manage_users.html` with user list

**Features:**
- Search users by username (case-insensitive)
- Filter by role
- Excludes current admin from list

---

### Delete User

**Endpoint:** `POST /delete_user/<user_id>`

**Description:** Delete a user account (Admin only)

**Access:** ADMIN only

**URL Parameters:**
- `user_id`: integer (user ID to delete)

**Request Body:**
```
csrf_token: string (required)
```

**Response:** Redirect to `/manage_users`

**Constraints:**
- Admin cannot delete their own account
- Cascading delete removes associated UserProfile

---

### Edit User Password

**Endpoint:** `POST /edit_user_password/<user_id>`

**Description:** Change another user's password (Admin only)

**Access:** ADMIN only

**URL Parameters:**
- `user_id`: integer (target user ID)

**Request Body:**
```
new_password: string (required, min 6 chars)
csrf_token: string (required)
```

**Response:** Redirect to `/index` with success message

**Database Operations:**
- Updates user password (hashed)
- Creates PasswordChangeLog entry

---

### Edit User Username

**Endpoint:** `POST /edit_user_username/<user_id>`

**Description:** Change another user's username (Admin only)

**Access:** ADMIN only

**URL Parameters:**
- `user_id`: integer (target user ID)

**Request Body:**
```
nuevo_username: string (required, 5-20 chars)
csrf_token: string (required)
```

**Response:** Redirect to `/manage_users` with success message

**Validation:**
- Username must be unique within the same role
- Updates both User and UserProfile tables

**Database Operations:**
- Updates username in User table
- Updates user_name in UserProfile table
- Creates UsernameChangeLog entry

---

## Candidate Routes

### Register Candidate

**Endpoint:** `POST /register_candidate`

**Description:** Register a new election candidate (Admin only)

**Access:** ADMIN only

**Method:** GET, POST

**Request Body:**
```
name: string (required, 4-50 chars)
last_name: string (required, 4-50 chars)
propuesta: string (required, campaign proposal)
profile_picture: file (optional, jpg/png/jpeg)
csrf_token: string (required)
```

**Response:**
- Success: Redirect to `/login` with success message
- Failure: Flash error message

**File Upload:**
- Photos saved to `static/candidate_photos/`
- Filename format: `{name}_{last_name}_{timestamp}.{ext}`
- Allowed formats: jpg, png, jpeg

---

### View Candidates

**Endpoint:** `GET /candidates`

**Description:** Display list of all candidates

**Access:** Authenticated users only

**Response:** Rendered `candidates_list.html` with all candidates

**Data Returned:**
- Candidate name, last name
- Campaign proposal
- Profile picture (if available)

---

## Voting Routes

### Vote

**Endpoint:** `POST /vote`

**Description:** Cast a vote for a candidate (Students only)

**Access:** ESTUDIANTE role only

**Method:** GET, POST

**Request Body:**
```
candidate_id: integer (required)
csrf_token: string (required)
```

**Response:**
- Success: Redirect to `/results`
- Already voted: Redirect to `/results` with warning
- Not a student: Redirect to `/index` with error

**Constraints:**
- One vote per user (enforced by database constraint)
- Only students can vote

**Security:**
- Vote is recorded with user_id (for uniqueness)
- Results are aggregated anonymously

---

### View Results

**Endpoint:** `GET /results`

**Description:** Display election results with vote counts and percentages

**Access:** Public (no login required)

**Response:** Rendered `results.html` with results data

**Data Structure:**
```json
{
  "results": [
    {
      "candidate": Candidate object,
      "votes": integer,
      "percentage": float (1 decimal)
    }
  ],
  "total_votes": integer,
  "has_voted": boolean (if authenticated)
}
```

**Features:**
- Results ordered by vote count (descending)
- Percentage calculated from total votes
- Shows if current user has voted

---

## Profile Management Routes

### View Profile

**Endpoint:** `GET /view_profile`

**Description:** Display current user's profile

**Access:** Authenticated users only

**Response:** Rendered `view_profile.html` with user data

---

### Edit Profile

**Endpoint:** `POST /edit_profile`

**Description:** Update user profile information

**Access:** Authenticated users only

**Method:** GET, POST

**Request Body:**
```
email: string (required, 4-50 chars)
name: string (required, 4-50 chars)
last_name: string (required, 4-50 chars)
profile_picture: file (optional, jpg/png/jpeg/webp)
csrf_token: string (required)
```

**Response:**
- Success: Redirect to `/index` with success message
- Failure: Flash error message

**Validation:**
- Email must be unique across all users
- Profile picture formats: jpg, jpeg, png, webp

**File Upload:**
- Photos saved to `uploads/photos/`
- Secure filename generation

---

### Change Password

**Endpoint:** `POST /change_password`

**Description:** Change own password

**Access:** Authenticated users only

**Method:** GET, POST

**Request Body:**
```
new_password: string (required, min 6 chars)
csrf_token: string (required)
```

**Response:** Redirect to `/index` with success message

**Database Operations:**
- Updates password (hashed)
- Creates PasswordChangeLog entry

---

### Edit Username

**Endpoint:** `POST /edit_username`

**Description:** Change own username

**Access:** Authenticated users only

**Method:** GET, POST

**Request Body:**
```
nuevo_username: string (required, 5-20 chars)
csrf_token: string (required)
```

**Response:** Redirect to `/index` with success message

**Validation:**
- Username must be unique within same role

**Database Operations:**
- Updates username in User table
- Updates user_name in UserProfile table
- Creates UsernameChangeLog entry

---

## Audit Log Routes

### View Username Logs

**Endpoint:** `GET /logs_username`

**Description:** View all username change logs (Admin only)

**Access:** ADMIN only

**Response:** Rendered `logs.html` with username change history

**Data Displayed:**
- Who made the change
- Affected user
- Old username
- New username
- Timestamp

---

### View Password Logs

**Endpoint:** `GET /logs_password`

**Description:** View all password change logs (Admin only)

**Access:** ADMIN only

**Response:** Rendered `logs_password.html` with password change history

**Data Displayed:**
- Who made the change
- Affected user
- Timestamp

---

### View All Logs

**Endpoint:** `GET /all_logs`

**Description:** View all system logs (username and password changes)

**Access:** ADMIN only

**Response:** Rendered `all_logs.html` with all audit logs

---

## Export Routes

### Export Username Logs (Excel)

**Endpoint:** `GET /export_logs_excel`

**Description:** Download username change logs as Excel file

**Access:** ADMIN only

**Response:** Excel file download (`cambios_username.xlsx`)

**File Format:**
- Sheet name: "Cambios de Username"
- Columns: #, Usuario que hizo el cambio, Usuario afectado, Username anterior, Username nuevo, Fecha y Hora
- Ordered by timestamp (descending)

---

### Export Username Logs (PDF)

**Endpoint:** `GET /export_logs_pdf`

**Description:** Download username change logs as PDF file

**Access:** ADMIN only

**Response:** PDF file download (`cambios_username.pdf`)

**File Features:**
- University logo (if available)
- Professional formatting
- Page numbers
- Timestamps
- Alternating row colors

---

### Export Password Logs (Excel)

**Endpoint:** `GET /export_password_logs_excel`

**Description:** Download password change logs as Excel file

**Access:** ADMIN only

**Response:** Excel file download (`cambios_contraseña.xlsx`)

**File Format:**
- Sheet name: "Cambios de Contraseña"
- Columns: #, Usuario que hizo el cambio, Usuario afectado, Fecha y Hora

---

### Export Password Logs (PDF)

**Endpoint:** `GET /export_password_logs_pdf`

**Description:** Download password change logs as PDF file

**Access:** ADMIN only

**Response:** PDF file download (`cambios_contraseña.pdf`)

---

### Export All Logs (Excel)

**Endpoint:** `GET /export_all_logs_excel`

**Description:** Download all system logs as Excel file with multiple sheets

**Access:** ADMIN only

**Response:** Excel file download (`logs_sistema.xlsx`)

**File Structure:**
- Sheet 1: Username changes
- Sheet 2: Password changes

---

### Export All Logs (PDF)

**Endpoint:** `GET /export_all_logs_pdf`

**Description:** Download all system logs as PDF file

**Access:** ADMIN only

**Response:** PDF file download (`todos_los_logs.pdf`)

**File Structure:**
- Section 1: Username change history
- Section 2: Password change history
- Professional formatting with headers and footers

---

## Static Routes

### Home

**Endpoint:** `GET /`

**Description:** Landing page for the application

**Access:** Public

**Response:** Rendered `home.html`

---

### Index

**Endpoint:** `GET /index`

**Description:** Main dashboard after login

**Access:** Authenticated users only

**Response:** Rendered `index.html`

---

### Uploaded Photos

**Endpoint:** `GET /uploads/photos/<filename>`

**Description:** Serve uploaded profile photos

**Access:** Public (but filenames are obscure)

**URL Parameters:**
- `filename`: string (photo filename)

**Response:** Image file from `uploads/photos/` directory

---

## Error Handling

### Common HTTP Status Codes

- **200 OK**: Successful GET request
- **302 Found**: Successful redirect
- **400 Bad Request**: Invalid form data
- **401 Unauthorized**: Not authenticated
- **403 Forbidden**: Not authorized (wrong role)
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

### Flash Message Categories

- `success`: Operation completed successfully
- `danger`: Error occurred
- `warning`: Warning (e.g., already voted)
- `info`: Informational message (e.g., logged out)

### Common Error Messages

| Message | Meaning |
|---------|---------|
| "No tienes permisos..." | User lacks required role/permissions |
| "Debes iniciar sesión..." | Login required |
| "Usuario o contraseña incorrectos" | Invalid credentials |
| "El usuario ya existe" | Username already taken |
| "Ya has emitido tu voto" | User already voted |
| "reCAPTCHA falló" | reCAPTCHA verification failed |

---

## Security Considerations

### CSRF Protection
All POST routes require valid CSRF tokens. Tokens are automatically generated by Flask-WTF.

### Password Security
- Passwords are hashed using Werkzeug's `generate_password_hash`
- Never stored or transmitted in plain text
- Minimum length: 6 characters

### Session Security
- Session cookies are httpOnly and secure (in production)
- Session timeout configured via Flask
- Login required decorator protects sensitive routes

### Input Validation
- All form inputs validated via WTForms validators
- File uploads restricted by extension
- SQL injection prevented via SQLAlchemy ORM

### Rate Limiting
- Login attempts limited to 3 per 15 seconds per username
- Failed attempts tracked in database

---

## Database Transactions

Most routes that modify data use the following pattern:

```python
try:
    # Database operations
    db.session.add(object)
    db.session.commit()
    flash("Success message", "success")
except Exception as e:
    db.session.rollback()
    flash("Error message", "danger")
```

This ensures data integrity and proper error handling.
