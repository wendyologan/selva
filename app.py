from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, SubmitField, HiddenField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError, DataRequired

from sqlalchemy import Column, Integer, ForeignKey, desc
from sqlalchemy.orm import relationship

import os
from flask_migrate import Migrate
from datetime import datetime, date

from werkzeug.security import generate_password_hash, check_password_hash

base_dir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(base_dir, 'instance')
app = Flask(__name__, instance_path=instance_path)

csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/wendylogan/selva/instance/entries.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized():
    # Check if the current route is the login route
    if request.endpoint == 'login':
        flash('Please log in to access this page.', 'error')
        return render_template('signin.html')

    # For other routes, redirect to the login page
    flash('Please log in to access this page.', 'error')
    return redirect(url_for('login'))

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The CSRF token has expired. Please try again.', 'danger')
    return redirect(url_for('client_dashboard'))

THERAPIST_ROLE = 'therapist'
PATIENT_ROLE = 'patient'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)

    def __init__(self, first_name, last_name, username, password, role=None):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password_hash = generate_password_hash(password)
        if role is not None:
            self.role = role

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get_by_id(user_id):
        return User.query.get(int(user_id))

    @property
    def full_name(self):
        return f"{self.last_name.capitalize()}, {self.first_name.capitalize()}"

class DiaryEntry(db.Model):
    __tablename__ = 'diary_entries'
    id = Column(Integer, primary_key=True)
    header = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    entry_date = db.Column(db.Date, nullable=False, default=db.func.current_date())  
    patient = db.relationship("Patient", back_populates="entries")

    def __init__(self, header, content, patient_id):
        self.header = header  
        self.content = content
        self.patient_id = patient_id

class Therapist(User):
    __tablename__ = 'therapists'
    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    patients = relationship("Patient", back_populates="therapist", foreign_keys="Patient.therapist_id")

    __mapper_args__ = {
        'polymorphic_identity': 'therapist',
        'inherit_condition': (id == User.id)
    }

    def __init__(self, first_name, last_name, username, password, role=THERAPIST_ROLE):
        super().__init__(first_name, last_name, username, password, role=role)

    def is_authenticated(self):
        return self.is_active()

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get_by_id(user_id):
        return Therapist.query.get(int(user_id))

    @property
    def full_name(self):
        return f"{self.last_name.capitalize()}, {self.first_name.capitalize()}"

class Patient(User):
    __tablename__ = 'patients'
    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    therapist_id = db.Column(db.Integer, db.ForeignKey('therapists.id'))
    therapist = db.relationship('Therapist', foreign_keys=[therapist_id], back_populates='patients')
    entries = db.relationship('DiaryEntry', back_populates='patient')

    __mapper_args__ = {
        'polymorphic_identity': 'patient',
        'inherit_condition': (id == User.id) 
    }

    def __init__(self, therapist=None, **kwargs):
        self.therapist = therapist
        super(Patient, self).__init__(**kwargs)

    @property
    def full_name(self):
        return f"{self.last_name.capitalize()}, {self.first_name.capitalize()}"

class ClientRegistrationForm(FlaskForm):
    first_name = StringField('First Name', [validators.InputRequired()])
    last_name = StringField('Last Name', [validators.InputRequired()])
    username = StringField('Username', [validators.InputRequired()])
    password = PasswordField('Password', [validators.InputRequired(), validators.Length(min=6)])
    confirm_password = PasswordField('Confirm Password', [validators.EqualTo('password', message='Passwords must match')])
    therapist = SelectField('Therapist', validators=[DataRequired()], coerce=int)
    def validate_therapist(self, therapist):
        if therapist.data == 'Select a therapist':
            raise ValidationError('Please select a therapist')

    submit = SubmitField('Register')

class TherapistRegistrationForm(FlaskForm):
    first_name = StringField('First Name', [InputRequired()])
    last_name = StringField('Last Name', [InputRequired()])
    username = StringField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired(), Length(min=6)])
    role = HiddenField(default='therapist')
    confirm_password = PasswordField('Confirm Password', [EqualTo('password', message='Passwords must match')])

class SigninForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

    def validate_username(form, field):
        allowed_roles = ['therapist', 'Therapist'] 
        if field.data not in allowed_roles:
            raise ValidationError('Invalid role. Please choose "therapist".')

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.route('/')
def main():
    if current_user.is_authenticated:
        if current_user.role == 'therapist':
            return redirect(url_for('therapist_dashboard'))
        elif current_user.role == 'patient':
            return redirect(url_for('client_dashboard'))

    error = request.args.get('error')
    error_field = request.args.get('error_field')
    return render_template('signin.html', error=error, error_field=error_field, errors={})

@app.route('/signin')
def signin():
    form = SigninForm()
    version = 1 

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'therapist':
                return redirect(url_for('therapist_dashboard'))
            elif user.role == 'patient':
                return redirect(url_for('client_dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    form_errors = form.errors

    return render_template('signin.html', version=version, form=form, errors=form_errors)

@app.route('/register_therapist', methods=['GET', 'POST'])
def register_therapist():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        errors = {}
        if len(username) < 4:
            errors['username'] = 'Username must be at least 4 characters long.'

        if len(password) < 6:
            errors['password'] = 'Password must be at least 6 characters long.'

        if password != confirm_password:
            errors['confirm_password'] = 'Passwords do not match.'

        # If validation errors, render template with errors
        if errors:
            return render_template('register-therapist.html', errors=errors)

        # If form data is valid, create a new therapist instance and save it to the database
        new_therapist = Therapist(
            first_name=first_name,
            last_name=last_name,
            username=username,
            password=password,
            role = 'therapist'
        )
        db.session.add(new_therapist)
        db.session.commit()

        flash('Registration successful, please sign in to access your account!', 'success')

        # Redirect user to login page after successful registration
        return redirect(url_for('login'))

    # If request method is GET, render the therapist registration form template
    return render_template('register-therapist.html', errors={})

@app.route('/register-client', methods=['GET', 'POST'])
def register_client():
    therapists = get_all_therapists()
    if not therapists:
        flash('There are currently no therapists registered. Please check back later.', 'info')

    form = ClientRegistrationForm()
    form.therapist.choices = [(therapist.id, therapist.full_name) for therapist in therapists]
    
    # Dictionary to store validation errors
    errors = {}

    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        username = form.username.data
        password = form.password.data
        therapist_id = form.therapist.data 

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different username.', 'error')
            return render_template('register-client.html', therapists=therapists, form=form)

        therapist = Therapist.query.get(therapist_id)

        new_client = Patient(
            username=username,
            password=password,
            role=PATIENT_ROLE,
            first_name=first_name,
            last_name=last_name,
            therapist=therapist
        )
        db.session.add(new_client)
        db.session.commit()

        flash('Registration successful, please sign in to access your account!', 'success')
        return redirect(url_for('login'))
    if not form.therapist.data:
        errors['therapist'] = 'Please select a therapist.'

    # Pass the `errors` dictionary to the template, even if it's empty
    return render_template('register-client.html', therapists=therapists, errors=errors, form=form)

@app.route('/therapist/dashboard/entries', methods=['GET'])
def get_diary_entries():
    therapist_id = current_user.get_id()
    entries = db.session.query(DiaryEntry) \
                .join(Patient, DiaryEntry.patient_id == Patient.id) \
                .filter(Patient.therapist_id == therapist_id) \
                .order_by(DiaryEntry.id.desc(), DiaryEntry.timestamp.desc()) \
                .all()

    # Convert the entries to a list of dictionaries for JSON serialization
    diary_entries = []
    for entry in entries:
        diary_entries.append({
            'client_id': entry.patient_id,
            'date': entry.entry_date.strftime('%Y-%m-%d'),
            'client_name': entry.patient.full_name,
            'header': entry.header,
            'id': entry.id
        })
    return jsonify(diary_entries)

def get_all_therapists():
    try:
        therapists = Therapist.query.all()
        return therapists  # Return the list of therapist objects
    except Exception as e:
        return []

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        therapist = Therapist.query.filter_by(username=username).first()

        if therapist and therapist.check_password(password):
            # Successful login for a therapist
            session['user_type'] = 'therapist'
            session['user_id'] = therapist.id
            login_user(therapist)
            return redirect(url_for('therapist_dashboard'))
        else:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                # Successful login
                login_user(user)
                if user.role == 'therapist':
                    # Redirect to therapist dashboard
                    return redirect(url_for('therapist_dashboard'))
                elif user.role == 'patient':
                    # Redirect to client dashboard
                    return redirect(url_for('client_dashboard'))
            else:
                # Incorrect credentials
                flash('Incorrect username or password. Please try again.', 'danger')
    return redirect(url_for('main'))

@app.route('/therapist/dashboard')
@login_required
def therapist_dashboard():
    therapist_id = current_user.get_id()
    patients = Patient.query.filter(Patient.therapist_id == therapist_id).all()

    # Check if the user is a therapist based on role
    if current_user.role == 'therapist':
        entries = DiaryEntry.query \
            .with_entities(DiaryEntry.id, DiaryEntry.entry_date, DiaryEntry.header, Patient) \
            .join(Patient, DiaryEntry.patient_id == Patient.id) \
            .filter(Patient.therapist_id == therapist_id) \
            .order_by(desc(DiaryEntry.timestamp)) \
            .all()
        return render_template('therapist_dashboard.html', patients=patients, entries=entries)

    flash('Please log in as a therapist to access this page.', 'danger')
    return redirect(url_for('main'))

@app.route('/client/dashboard', methods=['GET', 'POST'])
@login_required
def client_dashboard():
    # Check if the user is logged in and has the 'patient' role
    if not current_user.is_authenticated or current_user.role != 'patient':
        return redirect(url_for('main'))

    # Get the currently logged-in user's ID (client's ID)
    client_id = current_user.id

    # Check if the success flag is present in the session
    if session.pop('registration_success', False):
        flash('Registration successful, please sign in to access your account!', 'success')

    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if csrf_token != request.form.get('csrf_token'):
            return "CSRF token validation failed!", 403

        header = request.form.get('header')
        content = request.form.get('content')
        new_entry = DiaryEntry(patient_id=client_id, header=header, content=content)
        db.session.add(new_entry)

        try:
            db.session.commit()
            flash('Entry saved successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print("Database commit failed with error:", e)
            flash('Failed to save entry. Please try again later.', 'danger')

        # Redirect back to the client dashboard to show the flash message
        return redirect(url_for('client_dashboard'))

    try:
        # Query database to retrieve past entries for the client, ordered by timestamp (most recent first)
        entries = DiaryEntry.query.filter_by(patient_id=client_id).order_by(DiaryEntry.timestamp.desc()).all()
    except Exception as e:
        entries = []
        print("Error fetching diary entries:", e)
        flash('Failed to fetch diary entries. Please try again later.', 'danger')

    return render_template('client_dashboard.html', entries=entries)

@app.route('/diary_entry/<int:entry_id>')
def diary_entry(entry_id):
    entry = DiaryEntry.query.get(entry_id)
    if not entry:
        flash('Diary entry not found.', 'danger')
        return redirect(url_for('therapist_dashboard'))
    client_name = entry.patient.full_name
    return render_template('diary_entry.html', entry=entry, client_name=client_name)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # Logout the user using Flask-Login's logout_user() function
    logout_user()

    # Redirect the user back to the main page
    return redirect(url_for('main'))

def create_database_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_database_tables()
    app.run(debug=True)