from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from utils.token import generate_reset_token, verify_reset_token
from models import db, User, Project, Calls, Report, Meeting, Task, Account, Deals, Lead, Contact
from dotenv import load_dotenv
import pymysql
import os
pymysql.install_as_MySQLdb()
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Necessary for sessions
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')  # Update the database URI accordingly
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Migrate
db.init_app(app)
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')  # or your provider
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # never your real password!
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_logged_in():
    return 'user_id' in session  # Return True if user is logge
# Home Route
@app.route('/')
def home():
    return render_template('home.html', active_tab='home')

@app.route('/logout')
def logout():
    # Remove user_id from session to log out the user
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')  # You can display a flash message to inform the user
    return redirect(url_for('login'))  # Redirect to login page



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query the database to check if the user exists
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Store user ID in the session
            session['user_id'] = user.id

            # Redirect to home page or wherever
            return redirect(url_for('home'))

        else:
            # Flash error message for invalid credentials and redirect back to login
            flash('Invalid credentials. Please try again.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        role = 'USER'
        mobile = request.form.get('mobile', '')
        address = request.form.get('address', '')
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))

        # Hash the password before saving it
        hashed_password = generate_password_hash(password)

        # Create a new User object
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,
            mobile=mobile,
            address=address,
            password=hashed_password
        )

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

    
# Setup Route (User creation)
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    # Get the current logged-in user's role from the session
    user = User.query.get(session['user_id'])
    
    if user.role != "ADMIN":
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))  # Redirect to home or any other page
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        role = request.form['role']
        mobile = request.form['mobile']
        address = request.form['address']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))

        # Hash the password before saving it
        hashed_password = generate_password_hash(password)

        # Create a new User object
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,  # Will be 'USER' by default
            mobile=mobile,
            address=address,
            password=hashed_password
        )

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')

        return redirect(url_for('setup'))  # Redirect back to the setup page after submission

    # Fetch users from the database
    users = User.query.all()
    return render_template('setup.html', users=users)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password_token', token=token, _external=True)

            # Send Email
            msg = Message('Password Reset - WeConnect',
                          recipients=[user.email])
            msg.body = f'''Hi {user.first_name},

You requested a password reset. Click the link below to reset your password:

{reset_url}

If you did not request this, ignore this email.
'''
            mail.send(msg)

        flash('If this email exists in our system, a password reset link has been sent.', 'success')
        return redirect(url_for('reset_password_request'))

    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(request.url)

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password reset successful. Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password_form.html')

@app.route('/update_user', methods=['GET', 'POST'])
def update_user():
    if not is_logged_in():
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.role != 'ADMIN':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    search_email = request.form.get('search_email')
    found_user = None

    if request.method == 'POST' and search_email:
        found_user = User.query.filter_by(email=search_email).first()

    all_users = User.query.all()
    return render_template(
        'update_user.html',
        found_user=found_user,
        all_users=all_users,
        search_email=search_email
    )


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_logged_in():
        return redirect(url_for('login'))

    current = User.query.get(session['user_id'])
    if current.role != 'ADMIN':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.mobile = request.form['mobile']
        user.address = request.form['address']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!')
        return redirect(url_for('update_user'))

    return render_template('edit_user.html', user=user)


@app.route('/personal_settings')
def personal_settings():
    return render_template('personal_settings.html')

@app.route('/company_settings')
def company_settings():
    return render_template('company_settings.html')

# Contacts Route
@app.route('/contacts', methods=['GET', 'POST'])
def contacts():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        data = {
            'contact_first_name': request.form.get('first_name'),
            'contact_last_name': request.form.get('last_name'),
            'contact_email': request.form.get('email'),
            'contact_phone': request.form.get('phone'),
            'contact_company': request.form.get('company')
        }

        # Create and save new contact to the database
        new_contact = Contact(**data)
        db.session.add(new_contact)
        db.session.commit()

        print("Contact Submitted:", data)
        return redirect(url_for('contacts'))

    # Fetch contacts from the database
    contacts = Contact.query.all()
    return render_template('contacts.html', contacts=contacts)

@app.route('/profile')
def profile():
    if not is_logged_in():
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Get user from session
    return render_template('profile.html', user=user)



# Leads Route
@app.route('/leads', methods=['GET', 'POST'])
def leads():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        data = {
            'lead_owner': request.form.get('lead_owner'),
            'lead_first_name': request.form.get('first_name'),
            'lead_last_name': request.form.get('last_name'),
            'lead_email': request.form.get('email'),
            'lead_phone': request.form.get('phone'),
            'lead_source': request.form.get('lead_source'),
            'lead_status': request.form.get('status')
        }

        # Create and save new lead to the database
        new_lead = Lead(**data)
        db.session.add(new_lead)
        db.session.commit()

        print("Lead Submitted:", data)
        return redirect(url_for('leads'))

    # Fetch leads from the database
    leads = Lead.query.all()
    return render_template('leads.html', leads=leads)

# Deals Route
@app.route('/deals', methods=['GET', 'POST'])
def deals():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        data = {
            'deal_name': request.form.get('deal_name'),
            'account_name': request.form.get('account_name'),
            'deal_stage': request.form.get('deal_stage'),
            'deal_amount': request.form.get('amount'),
            'deal_close_date': request.form.get('close_date')
        }

        # Create and save new deal to the database
        new_deal = Deals(**data)
        db.session.add(new_deal)
        db.session.commit()

        print("Deal Submitted:", data)
        return redirect(url_for('deals'))

    # Fetch deals from the database
    deals = Deals.query.all()
    return render_template('deals.html', deals=deals)

# Accounts Route
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        data = {
            'account_name': request.form.get('account_name'),
            'account_type': request.form.get('type'),
            'billing_country': request.form.get('billing_country'),
            'billing_state': request.form.get('billing_state')
        }

        # Create and save new account to the database
        new_account = Account(**data)
        db.session.add(new_account)
        db.session.commit()

        print("Account Submitted:", data)
        return redirect(url_for('accounts'))

    # Fetch accounts from the database
    accounts = Account.query.all()
    return render_template('accounts.html', accounts=accounts)

# Tasks Route
@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        task_name = request.form['task_name']
        due_date = request.form['due_date']
        assigned_to = request.form['assigned_to']
        status = request.form['status']

        # Create and save new task to the database
        new_task = Task(task_name=task_name, task_due_date=due_date, task_assignee=assigned_to, task_status=status)
        db.session.add(new_task)
        db.session.commit()

        print("Task Submitted:", {'task_name': task_name, 'due_date': due_date, 'assigned_to': assigned_to, 'status': status})
        return redirect(url_for('tasks'))

    # Fetch tasks from the database
    tasks = Task.query.all()
    return render_template('tasks.html', tasks=tasks)

# Meetings Route
@app.route('/meetings', methods=['GET', 'POST'])
def meetings():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        meeting_title = request.form['meeting_title']
        meeting_date = request.form['meeting_date']
        meeting_time = request.form['meeting_time']
        attendees = request.form['attendees']

        # Create and save new meeting to the database
        new_meeting = Meeting(meeting_title=meeting_title, meeting_date=meeting_date, meeting_time=meeting_time, meeting_attendees=attendees)
        db.session.add(new_meeting)
        db.session.commit()

        print("Meeting Submitted:", {'meeting_title': meeting_title, 'meeting_date': meeting_date, 'meeting_time': meeting_time, 'attendees': attendees})
        return redirect(url_for('meetings'))

    # Fetch meetings from the database
    meetings = Meeting.query.all()
    return render_template('meetings.html', meetings=meetings)

# Reports Route
@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        report_title = request.form['report_title']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        report_type = request.form['report_type']

        # Create and save new report to the database
        new_report = Report(report_title=report_title, report_date_from=start_date, report_date_from_to=end_date, report_type=report_type)
        db.session.add(new_report)
        db.session.commit()

        print("Report Submitted:", {'report_title': report_title, 'start_date': start_date, 'end_date': end_date, 'report_type': report_type})
        return redirect(url_for('reports'))

    # Fetch reports from the database
    reports = Report.query.all()
    return render_template('reports.html', reports=reports)

# Calls Route
@app.route('/calls', methods=['GET', 'POST'])
def calls():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        caller_name = request.form['caller_name']
        call_type = request.form['call_type']
        call_duration = request.form['call_duration']
        call_notes = request.form['call_notes']

        # Create and save new call to the database
        new_call = Calls(caller_name=caller_name, call_type=call_type, call_duration=call_duration, note=call_notes)
        db.session.add(new_call)
        db.session.commit()

        print("Call Submitted:", {'caller_name': caller_name, 'call_type': call_type, 'call_duration': call_duration, 'call_notes': call_notes})
        return redirect(url_for('calls'))

    # Fetch calls from the database
    calls = Calls.query.all()
    return render_template('calls.html', calls=calls)

# Projects Route
@app.route('/projects', methods=['GET', 'POST'])
def projects():
    if not is_logged_in():
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Extracting form data
        project_name = request.form['project_name']
        project_status = request.form['project_status']
        due_date = request.form['due_date']
        description = request.form['description']

        # Create and save new project to the database
        new_project = Project(projectName=project_name, projectStatus=project_status, projectDueDate=due_date, projectDescription=description)
        db.session.add(new_project)
        db.session.commit()

        print("Project Submitted:", {'project_name': project_name, 'project_status': project_status, 'due_date': due_date, 'description': description})
        return redirect(url_for('projects'))

    # Fetch projects from the database
    projects = Project.query.all()
    return render_template('projects.html', projects=projects)

# Run the app
if __name__ == '__main__':
    app.run()
