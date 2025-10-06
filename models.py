from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy object (to be imported in app.py)
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    mobile = db.Column(db.String(50), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(80), nullable=False)
    project_description = db.Column(db.String(200), nullable=False)
    project_status = db.Column(db.String(50), nullable=False)
    project_due_date = db.Column(db.DateTime, nullable=False)  # Consider db.Date if no time is needed

class Calls(db.Model):  # Renamed to 'Call' for consistency with the class name
    id = db.Column(db.Integer, primary_key=True)
    caller_name = db.Column(db.String(80), nullable=False)
    call_type = db.Column(db.String(50), nullable=False)
    call_duration = db.Column(db.Integer, nullable=False)  # In minutes?
    note = db.Column(db.String(200), nullable=True)  # Changed to nullable=True, since notes might be optional

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_title = db.Column(db.String(80), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    report_date_from = db.Column(db.DateTime, nullable=False)
    report_date_to = db.Column(db.DateTime, nullable=False)  # Renamed to 'report_date_to' for clarity

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meeting_title = db.Column(db.String(80), nullable=False)
    meeting_date = db.Column(db.DateTime, nullable=False)
    meeting_time = db.Column(db.DateTime, nullable=False)
    meeting_attendees = db.Column(db.String(255), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(80), nullable=False)
    task_due_date = db.Column(db.DateTime, nullable=False)
    task_status = db.Column(db.String(50), nullable=False)
    task_assignee = db.Column(db.String(80), nullable=False)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(80), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    billing_country = db.Column(db.String(50), nullable=False)
    billing_state = db.Column(db.String(50), nullable=False)

class Deals(db.Model):  # Renamed to 'Deal' to match singular form
    id = db.Column(db.Integer, primary_key=True)
    deal_name = db.Column(db.String(80), nullable=False)
    account_name = db.Column(db.String(80), nullable=False)
    deal_amount = db.Column(db.Float, nullable=False)
    deal_stage = db.Column(db.String(50), nullable=False)
    deal_close_date = db.Column(db.DateTime, nullable=False)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lead_owner = db.Column(db.String(80), nullable=False)
    lead_first_name = db.Column(db.String(80), nullable=False)
    lead_last_name = db.Column(db.String(80), nullable=False)
    lead_email = db.Column(db.String(80), nullable=False)
    lead_phone = db.Column(db.String(20), nullable=False)
    lead_source = db.Column(db.String(50), nullable=False)
    lead_status = db.Column(db.String(50), nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contact_first_name = db.Column(db.String(80), nullable=False)
    contact_last_name = db.Column(db.String(80), nullable=False)
    contact_email = db.Column(db.String(80), nullable=False)
    contact_phone = db.Column(db.String(20), nullable=False)
    contact_company = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<Contact {self.contact_first_name} {self.contact_last_name}>'
