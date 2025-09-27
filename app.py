import os
import random
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, HiddenField
from wtforms.validators import DataRequired, Length, AnyOf
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

# Load environment variables from .env
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # For Flask session & WTF CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# AES setup
raw_key = os.getenv("AES_SECRET_KEY")
if not raw_key:
    raise ValueError("AES_SECRET_KEY environment variable is required")
AES_SECRET_KEY = raw_key.strip()
# Ensure key length is valid
if len(AES_SECRET_KEY) not in (16, 24, 32):
    raise ValueError("AES_SECRET_KEY must be 16, 24, or 32 bytes long")

# AES block size
BLOCK_SIZE = 16

# Define allowed roles explicitly
ALLOWED_ROLES = ['user', 'admin']

# Encrypt password before storing
def encrypt_password(plain_text):
    # Create cipher
    cipher = AES.new(AES_SECRET_KEY.encode(), AES.MODE_CBC)
    # Pad and encrypt
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), BLOCK_SIZE))
    # Encode IV and ciphertext to base64 for storage
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

# Decrypt password for verification
def decrypt_password(enc_text):
    # Split the IV and ciphertext
    iv_str, ct_str = enc_text.split(":")
    # Decode from base64
    iv = b64decode(iv_str)
    ct = b64decode(ct_str)
    # Create cipher
    cipher = AES.new(AES_SECRET_KEY.encode(), AES.MODE_CBC, iv)
    # Unpad and decode
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt.decode('utf-8')

# Database model for users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")
    balance = db.Column(db.Float, nullable=False, default=0.0)

    # Verify password
    def check_password(self, password):
        decrypted = decrypt_password(self.encrypted_password)
        return decrypted == password

    # Required by Flask-Login
    def get_id(self):
        return str(self.id)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Registration form with no role selection to prevent privilege escalation
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# Form for changing user roles (admin only)
class RoleChangeForm(FlaskForm):
    user_id = HiddenField('User ID', validators=[DataRequired()])
    new_role = SelectField('New Role', choices=[(r, r.capitalize()) for r in ALLOWED_ROLES], validators=[
        DataRequired(),
        AnyOf(ALLOWED_ROLES, message="Invalid role selected")
    ])
    submit = SubmitField('Update Role')

# Form for deleting a user account (admin only)
class AccountDeletionForm(FlaskForm):
    user_id = HiddenField('User ID', validators=[DataRequired()])
    submit = SubmitField('Delete Account')

# Home route
@app.route('/')
@login_required
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):

            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already taken.', 'danger')
            return render_template('register.html', form=form)
        
        encrypted_pw = encrypt_password(form.password.data)
        #Random balance for demonstration purposes
        random_balance = round(random.uniform(0, 1000), 2)

        user = User(
            username=form.username.data,
            encrypted_password=encrypted_pw,
            role='user',  #Hard coded role to prevent privilege escalation
            balance=random_balance
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Admin route to manage user roles
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('home'))

    users = User.query.order_by(User.username).all()
    role_forms = {}
    delete_forms = {}

    if request.method == 'POST':
        # Handle role change
        if 'new_role' in request.form:
            user_id = request.form.get("user_id")
            new_role = request.form.get("new_role")

            if user_id and new_role:
                user = User.query.get(int(user_id))
                if user:
                    if user.id == current_user.id:
                        flash("You cannot change your own role.", "warning")
                    else:
                        user.role = new_role
                        db.session.commit()
                        flash(f"Role updated for {user.username} to {new_role}.", "success")
                return redirect(url_for('admin'))

        # Handle account deletion
        elif 'delete_account' in request.form:
            user_id = request.form.get("user_id")
            user = User.query.get(int(user_id))
            if user:
                if user.id == current_user.id:
                    flash("You cannot delete your own account.", "warning")
                else:
                    db.session.delete(user)
                    db.session.commit()
                    flash(f"Account for {user.username} has been deleted.", "info")
            return redirect(url_for('admin'))

    # Prepare forms for each user
    for user in users:
        role_form = RoleChangeForm()
        role_form.user_id.data = user.id
        role_form.new_role.data = user.role
        role_forms[user.id] = role_form

        delete_form = AccountDeletionForm()
        delete_form.user_id.data = user.id
        delete_forms[user.id] = delete_form

    return render_template('admin.html', users=users, role_forms=role_forms, delete_forms=delete_forms)



# Create DB and default admin user on first run
first_run_done = False

# Ensure tables are created and default users exist
@app.before_request
def create_tables_and_admin():
    global first_run_done
    if not first_run_done:
        db.create_all()
        if not User.query.first():
            # Create a default admin user
            default_admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
            default_admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
            encrypted_pw = encrypt_password(default_admin_password)
            admin_user = User(
                username=default_admin_username,
                encrypted_password=encrypted_pw,
                role="admin",
                balance=0.0
            )
            db.session.add(admin_user)
            db.session.commit()
            print(f"Admin created: {default_admin_username} / {default_admin_password}", flush=True)
            
            # Create a default test user
            default_user_username = os.getenv("DEFAULT_USER_USERNAME", "test")
            default_user_password = os.getenv("DEFAULT_USER_PASSWORD", "test123")
            encrypted_pw = encrypt_password(default_user_password)
            test_user = User(
                username=default_user_username,
                encrypted_password=encrypted_pw,
                role="user",
                balance=1337.0
            )
            db.session.add(test_user)
            db.session.commit()
            print(f"Test User created: {default_user_username} / {default_user_password}", flush=True)
        first_run_done = True

# Run the app
if __name__ == '__main__':
    app.run(debug=True)