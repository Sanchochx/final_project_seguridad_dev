from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed 

class LoginForm(FlaskForm):
    """
    User login form with CSRF protection.

    Fields:
        username: Username field (4-50 chars, required)
        password: Password field (required)
        submit: Submit button

    Validators:
        - DataRequired on all fields
        - Length validation on username (4-50 chars)

    Security:
        - CSRF protection enabled via FlaskForm
        - Used with reCAPTCHA verification in login route
    """
    username = StringField('Usuario', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class RegisterForm(FlaskForm):
    """
    User registration form for creating new users (Admin only).

    Fields:
        username: Username field (4-50 chars, required)
        password: Password field (required)
        submit: Submit button

    Validators:
        - DataRequired on all fields
        - Length validation on username (4-50 chars)

    Usage:
        Used by admins to create new users with specific roles
    """
    username = StringField('Usuario', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Registrar')

class RegisterCandidate(FlaskForm):
    """
    Candidate registration form (Admin only).

    Fields:
        name: Candidate's first name (4-50 chars, required)
        last_name: Candidate's last name (4-50 chars, required)
        propuesta: Campaign proposal (required)
        profile_picture: Optional candidate photo (jpg, png, jpeg only)

    Validators:
        - DataRequired on name, last_name, propuesta
        - Length validation on name and last_name (4-50 chars)
        - FileAllowed on profile_picture (jpg, png, jpeg)

    Usage:
        Used by admins to register election candidates
    """
    name = StringField('Nombre', validators=[DataRequired(), Length(min=4, max=50)])
    last_name = StringField('Apellido', validators=[DataRequired(), Length(min=4, max=50)])
    propuesta = StringField('Propuesta', validators=[DataRequired()])
    profile_picture = FileField('Imagen de perfil', validators=[FileAllowed(['jpg', 'png', 'jpeg'], '¡Solo imágenes!')])

class EditProfileForm(FlaskForm):
    """
    User profile editing form.

    Fields:
        email: Email address (4-50 chars, required)
        name: First name (4-50 chars, required)
        last_name: Last name (4-50 chars, required)
        profile_picture: Optional profile photo (jpg, png, jpeg only)
        submit: Submit button

    Validators:
        - DataRequired on email, name, last_name
        - Length validation (4-50 chars)
        - FileAllowed on profile_picture (jpg, png, jpeg)

    Notes:
        - Email must be unique across all users
        - Profile picture is validated for allowed extensions
    """
    email = StringField('Email', validators=[DataRequired(), Length(min=4, max=50)])
    name = StringField('Nombre', validators=[DataRequired(), Length(min=4, max=50)])
    last_name = StringField('Apellido', validators=[DataRequired(), Length(min=4, max=50)])
    profile_picture = FileField('Imagen de perfil', validators=[FileAllowed(['jpg', 'png', 'jpeg'], '¡Solo imágenes!')])
    submit = SubmitField('Guardar cambios')

class ChangePasswordForm(FlaskForm):
    """
    Password change form.

    Fields:
        new_password: New password (min 6 chars, required)
        submit: Submit button

    Validators:
        - DataRequired on new_password
        - Length validation (min 6 chars)

    Usage:
        - Used by users to change their own password
        - Used by admins to change other users' passwords
    """
    new_password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Actualizar Contraseña')

class EditUsernameForm(FlaskForm):
    """
    Username change form.

    Fields:
        nuevo_username: New username (5-20 chars, required)
        submit: Submit button

    Validators:
        - DataRequired on nuevo_username
        - Length validation (5-20 chars)

    Notes:
        - Username must be unique within the same role
        - Change is logged in UsernameChangeLog table
    """
    nuevo_username = StringField('Nuevo Username', validators=[DataRequired(), Length(min=5, max=20)])
    submit = SubmitField('Actualizar Username')