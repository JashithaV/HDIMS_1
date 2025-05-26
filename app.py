from flask import Flask, render_template, request, redirect, url_for, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import json
from flask import flash, get_flashed_messages
from flask import session
from collections import defaultdict
#FOR PATIENT DB
import sqlite3
import os
from sqlalchemy import func
#For OTP CODE
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import requests
from datetime import date
from config import FIELD_TABLE_MAP, FIELD_CONFIG, CHART_TYPE_MAP
from sqlalchemy import text
#for signup to check hosp_id
from models.models import Hospital
#Ends here the import for sign up

db=SQLAlchemy();
app = Flask(__name__)
app.secret_key = '…'

# compute absolute path to hdims.db
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'db', 'hdims.db')

# point SQLAlchemy at hdims.db
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

print("→ SQLALCHEMY_DATABASE_URI =", app.config['SQLALCHEMY_DATABASE_URI'])
print("→ File exists?         ", os.path.exists(db_path))
#db.init_app(app);

#DATABASE CREATION FOR PATIENTS
os.makedirs("db", exist_ok=True)

db_path = "db/hdims.db"

def create_centralized_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Hospitals table - manually provided hospital_id (NO AUTOINCREMENT)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hospitals (
            hospital_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            hospital_code TEXT UNIQUE NOT NULL,
            location TEXT
        )
    ''')

    # Patients table with foreign key to hospitals
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            dob TEXT,
            contact_info TEXT,
            weight REAL,
            height REAL,
            blood_pressure TEXT,
            temperature REAL,
            blood_sugar REAL,
            department TEXT,
            doctor TEXT,
            disease TEXT,
            lab_reports TEXT,
            policy_involvement TEXT,
            policy_schema TEXT,
            past_illness TEXT,
            allergies TEXT,
            previous_treatments TEXT,
            family_history TEXT,
            admission_date TEXT,
            discharge_date TEXT,
            FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
        )
    ''')

    # Policy Inputs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_inputs (
            id INTEGER PRIMARY KEY,
            program_name TEXT NOT NULL,
            proposed_date TEXT,
            start_date TEXT,
            end_date TEXT,
            description TEXT,
            key_area TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Centralized database created.")
#DATABSE CREATION ENDS

class Hospital(db.Model):
    __tablename__ = 'hospitals'
    hospital_id = db.Column(db.Integer, primary_key=True)  # manually entered
    name = db.Column(db.String(150), nullable=False)
    hospital_code = db.Column(db.String(100), unique=True, nullable=False)
    location = db.Column(db.String(150), nullable=True)



#For OTP
# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'jaanuuvemu@gmail.com'  # Must be a real Gmail
app.config['MAIL_PASSWORD'] = 'kcmeepzqfeluqvwc'     # Not your regular password
app.config['MAIL_DEFAULT_SENDER'] = 'jaanuuvemu@gmail.com'
# OTP storage (in production, use Redis or database)
otp_storage = {}#ENDS OTP


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    hospital_id = db.Column(db.String(20), db.ForeignKey('hospitals.hospital_id'), nullable=True)  # FK to hospitals
    department = db.Column(db.String(100), nullable=True)


def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email)

def is_strong_password(password):
    return re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$", password)
#FOR SIGNUP OTP EXTRA
def send_otp_email(recipient_email, otp):
    subject = "Your OTP Verification Code"
    body = f"Your OTP code is: {otp}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "jashitha2006@gmail.com"
    msg["To"] = recipient_email

    # Use your SMTP config with SSL on port 465
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login("jashitha2006@gmail.com", "asvblbrkpbgsarpu")
            server.sendmail(msg["From"], [msg["To"]], msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")

#FOR SIGNUP OTP EXTRA ENDS

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    errors = {}
    show_otp = False

    if request.method == 'POST':
        if 'pending_signup' in session and 'otp' in request.form:
            # OTP Verification Step
            entered_otp = request.form.get('otp')
            otp_in_session = session.get('otp')
            signup_data = session.get('pending_signup')
            
            if entered_otp == otp_in_session:
                new_user = User(
                    role=signup_data['role'],
                    username=signup_data['username'],
                    email=signup_data['email'],
                    password=signup_data['password'],
                    hospital_id=signup_data['hospital_id'],
                    department=signup_data['department']
                )
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                print("Session user_id set to:", session['user_id'])
                session['role'] = new_user.role
                session.pop('pending_signup', None)
                session.pop('otp', None)
                flash("Signup successful!", "success")

                if new_user.role == "superadmin":
                    return redirect(url_for('superadmin_dashboard'))
                elif new_user.role == "hospitaladmin":
                    return redirect(url_for('hospitaladmin_dashboard'))
                elif new_user.role == "departmentstaff":
                    return redirect(url_for('deptadmin_dashboard'))
            else:
                errors['otp'] = "Invalid OTP!"
                show_otp = True
                return render_template('signup.html', errors=errors, show_otp=show_otp, form_data=signup_data)

        else:
            # Form Submission Step
            role = request.form.get('role')
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm-password')
            hospital_id = request.form.get('hospital_id')
            department=request.form.get('department')

            form_data = {
                'role': role,
                'username': username,
                'email': email,
                'hospital_id': hospital_id
            }

            if not is_valid_email(email):
                errors['email'] = "Invalid email format!"
            if not is_strong_password(password):
                errors['password'] = "Weak password! Include one Upper case, special charcater and a number"
            if password != confirm_password:
                errors['confirm_password'] = "Passwords do not match!"
            if role in ['hospitaladmin', 'departmentstaff']:
                if not hospital_id:
                    errors['hospital_id'] = "Hospital ID is required!"
                elif not Hospital.query.filter_by(hospital_id=hospital_id).first():
                    errors['hospital_id'] = "Invalid Hospital ID!"
            if role == 'departmentstaff' and not department:
                errors['department'] = "Department is required!"
            if User.query.filter_by(email=email).first():
                errors['email'] = "Email already registered!"

            if errors:
                return render_template('signup.html', errors=errors, show_otp=False, form_data=form_data)

            # Valid data, generate OTP and store signup info
            otp = str(random.randint(100000, 999999))
            send_otp_email(email, otp)
            session['otp'] = otp
            session['pending_signup'] = {
                'role': role,
                'username': username,
                'email': email,
                'password': generate_password_hash(password),
                'hospital_id': hospital_id,
                'department': department
            }

            flash("OTP sent to your email. Enter it below to complete signup.", "info")
            show_otp = True
            return render_template('signup.html', errors={}, show_otp=show_otp, form_data=session['pending_signup'])

    return render_template('signup.html', errors={}, show_otp=False, form_data={})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        errors = {}
        selected_role = request.form.get('role')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            errors['email'] = "Invalid Mail ID"
        else:
            if user.role != selected_role:
                errors['password'] = "Invalid Credentials"
            elif not check_password_hash(user.password, password):
                errors['password'] = "Invalid Password"
            else:
                     # ✅ Store session data
                session['user_id'] = user.id
                session['role'] = user.role
                session['hospital_id'] = user.hospital_id

                if selected_role == "superadmin":
                    return redirect(url_for('superadmin_dashboard'))
                elif selected_role == "hospitaladmin":
                    return redirect(url_for('hospitaladmin_dashboard'))
                elif selected_role == "departmentstaff":
                    return redirect(url_for('deptadmin_dashboard'))

        if errors:
            flash(json.dumps(errors), 'login_errors')  # Store errors in flash
            return redirect(url_for('login'))  # Redirect back to login page

    # GET request - check for flashed errors
    errors = {}
    error_data = get_flashed_messages(category_filter=['login_errors'])
    if error_data:
        try:
            errors = json.loads(error_data[0])
        except:
            pass

    return render_template('login_pg.html', errors=errors)

#CODE FOR LOGGING OUT for superamdin
@app.route('/logout')
def logout():
    session.clear()  # This clears all session data
    flash("You have been logged out", "success")
    return render_template('superadmin.html',errors={})  # Ensure 'superadmin_login' route exists
#CODE FOR LOGGING OUT for superamdin ENDS

#CODE FOR HOSPITAL ADMIN LOGOUT AND DEPTADMIN
@app.route('/logouthosp')
def logouthosp():
    return render_template('login_pg.html', errors={})
#CODE FOR HOSPITAL ADMIN LOG OUT ENDS

@app.route('/')
def home():
    return redirect(url_for('signup'))  # or 'login'

# Dashboards for respective roles
@app.route('/superadmin_dashboard',methods=['GET'])
def superadmin_dashboard():
    if 'user_id' not in session:
        flash("You must log in first", "error")
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line

    # Connect to the database
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Total Hospitals
    cursor.execute("SELECT COUNT(*) FROM hospitals")
    total_hospitals = cursor.fetchone()[0]

    # Total Patients (under treatment)
    cursor.execute("SELECT COUNT(*) FROM patients WHERE discharge_date IS NULL")
    total_patients = cursor.fetchone()[0]

    # Active Programs
    current_date = datetime.now().date()
    cursor.execute("SELECT COUNT(*) FROM policy_inputs WHERE end_date >= ?", (current_date,))
    active_programs = cursor.fetchone()[0]

    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "hospital_id": user["hospital_id"]
        }
    else:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))

    conn.close()
    # Pass values to the template
    return render_template('superadmin_dsh.html',
                           total_hospitals=total_hospitals,
                           total_patients=total_patients,
                           active_programs=active_programs,
                           user=user_info)

@app.route('/hospitaladmin_dashboard')
def hospitaladmin_dashboard():
    if 'user_id' not in session:
        flash("You must log in first", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line
    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "hospital_id": user["hospital_id"]
        }
    else:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))

    return render_template('hospadmin.html',user=user_info)

@app.route('/deptadmin_dashboard')
def deptadmin_dashboard():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id,department FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"],
                "department": user["department"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        dept = user['department']
        today = date.today().isoformat()
        
        cursor.execute("""
        SELECT COUNT(*) FROM patients 
         WHERE department = ? 
        AND admission_date <= ?
        AND (discharge_date IS NULL OR discharge_date > ?)
        """, (dept, today, today))
        total_patients = cursor.fetchone()[0]

    # Admission rate: patients admitted today
        cursor.execute("SELECT COUNT(*) FROM patients WHERE department = ? AND admission_date = ?", (dept, today))
        admission_rate = cursor.fetchone()[0]

    # Discharge rate: patients discharged today
        cursor.execute("SELECT COUNT(*) FROM patients WHERE department = ? AND discharge_date = ?", (dept, today))
        discharge_rate = cursor.fetchone()[0]
        return render_template('deptadmin.html',user=user_info,dept=user["department"],
                           total_patients=total_patients,
                           admission_rate=admission_rate,
                           discharge_rate=discharge_rate)

@app.route ('/data_entry_dept')
def data_entry_dept():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        return render_template('data_entry_dept.html',user=user_info)

@app.route ('/update_data_dept')
def update_data_dept():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        return render_template('update_data_dept.html',user=user_info)
#CODE FOR HOSPITAL ADMIN DASHBOARD
from flask import session
#CODE FOR HOSP ADMIN DSHBOARD TO GET DEPARTMENTS
@app.route('/api/departments', methods=['GET'])
def get_departments():
    hospital_id = session.get('hospital_id')
    if not hospital_id:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('db/hdims.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT DISTINCT department FROM patients
            WHERE hospital_id = ? AND department IS NOT NULL AND department != ''
        ''', (hospital_id,))
        departments = [row[0] for row in cursor.fetchall()]
        return jsonify(departments)

    except Exception as e:
        print("Error fetching departments:", e)
        return jsonify({'error': 'Failed to fetch departments'}), 500

    finally:
        conn.close()

#CODE FOR HOSPADMIN DASHBOARD TO GET DEPARTMNETS ENDS 

@app.route('/api/department/<department>', methods=['GET'])
def get_department_data(department):
    hospital_id = session.get('hospital_id')  # Ensure hospital_id is set at login
    if not hospital_id:
        return jsonify({'error': 'Unauthorized access'}), 401

    conn = sqlite3.connect('db/hdims.db')
    cursor = conn.cursor()

    try:
        print(f"Received department: {department} for hospital ID: {hospital_id}")

        # Count only patients from that department and that hospital
        cursor.execute('SELECT COUNT(*) FROM patients WHERE department = ? AND hospital_id = ?', (department, hospital_id))
        total_patients = cursor.fetchone()[0]
        print("Total Patients: ",total_patients)

        '''cursor.execute('SELECT COUNT(*) FROM program_entry WHERE department = ? AND hospital_id = ?', (department, hospital_id))
        programs_in_progress = cursor.fetchone()[0]'''

        # For discharge rate, consider total patients from this hospital
        cursor.execute('SELECT COUNT(*) FROM patients WHERE hospital_id = ?', (hospital_id,))
        total_all_patients = cursor.fetchone()[0]
        print("Total all Patients: ",total_all_patients)

        if total_patients != 0:
            cursor.execute('SELECT COUNT(*) FROM patients WHERE discharge_date IS NOT NULL AND department = ? AND hospital_id = ?', (department, hospital_id))
            discharged = cursor.fetchone()[0]
            discharge_rate = (discharged * 100.0) / total_patients
        else:
            discharge_rate = 0

        print("Discharge Rate: ",discharge_rate)

        cursor.execute('SELECT COUNT(*) FROM patients WHERE admission_date IS NOT NULL AND department = ? AND hospital_id = ?', (department, hospital_id))
        admissions = cursor.fetchone()[0]
        print("Admissions: ",admissions)

        return jsonify({
            'total_patients': total_patients,
            'discharge_rate': round(discharge_rate, 2),
            'admissions': admissions
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Data fetch failed'}), 500
    finally:
        conn.close()
#CODE FOR HOSPITAL ADMIN DASHBOARD ENDS HERE

#For announcements
@app.route("/get_announcements")
def get_announcements():
    try:
        conn = sqlite3.connect("db/hdims.db")  # ✅ Use correct path
        conn.row_factory = sqlite3.Row  # Allow column access by name
        cursor = conn.cursor()

        # Only get programs that are considered as announcements (e.g., active or recently added)
        cursor.execute("""
            SELECT id, program_name, start_date 
            FROM policy_inputs
            ORDER BY start_date DESC 
            LIMIT 5
        """)
        results = cursor.fetchall()

        # Convert rows to dictionary format
        announcements = [
            {
                "program_id": row["id"],
                "title": row["program_name"],
                "date": row["start_date"]
            }
            for row in results
        ]

        return jsonify(announcements)

    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({"error": "Failed to fetch announcements"}), 500

    finally:
        if conn:
            conn.close()
#Code for announcements ends

#Displaying all the policies code through announcemnets starts here
@app.route('/display_policy')
def display_policy():
    try:
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT id as program_id, program_name, proposed_date, start_date, end_date, description, key_area FROM policy_inputs ORDER BY start_date DESC")
        policies = cursor.fetchall()

        return render_template('display_policy.html', policies=policies)

    except sqlite3.Error as e:
        print("Database error:", e)
        return "Error loading policy data", 500

    finally:
        conn.close()

@app.route('/superadmin', methods=['GET', 'POST'])
def superadmin_login():
    if request.method == 'POST':
        errors = {}
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        print(f"Login attempt - Username: {username}, Password provided: {bool(password)}, OTP provided: {bool(otp)}")

        # First validate username and role
        user = User.query.filter_by(email=username).first()
        if not user:
            errors['username'] = "Invalid Mail ID"
            print("Invalid username")
        elif user.role != "superadmin":
            errors['username'] = "Not a superadmin account"
            print("Not a superadmin account")
        
        # If username and role are valid, check password
        if not errors.get('username'):
            print("Username valid, checking password")
            if not check_password_hash(user.password, password):
                errors['password'] = "Invalid Password"
                print("Invalid password")
                flash(json.dumps(errors), 'superadmin_errors')
                return redirect(url_for('superadmin_login'))
            
            print("Password valid, checking OTP")
            # Only verify OTP if username, role and password are correct
            if not otp:
                errors['otp'] = "OTP is required"
                print("OTP missing")
            else:
                try:
                    response = requests.post(
                        'http://localhost:5000/verify_otp',
                        json={'email': username, 'otp': otp},
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    response_data = response.json()
                    print(f"OTP verification response: {response_data}")
                    
                    if response_data.get('success'):
                        print("OTP valid, setting session")
                        # Set session data
                        session['user_id'] = user.id
                        session['role'] = user.role
                        return redirect(url_for('superadmin_dashboard'))
                    else:
                        errors['otp'] = "Invalid OTP"
                        print("Invalid OTP")
                except Exception as e:
                    print(f"Error during OTP verification: {str(e)}")
                    errors['otp'] = "Error verifying OTP"

        if errors:
            print(f"Errors found: {errors}")
            flash(json.dumps(errors), 'superadmin_errors')
            return redirect(url_for('superadmin_login'))

    # GET request - check for flashed errors
    errors = {}
    error_data = get_flashed_messages(category_filter=['superadmin_errors'])
    if error_data:
        try:
            errors = json.loads(error_data[0])
        except:
            pass

    return render_template('superadmin.html', errors=errors)

@app.route('/data_entry',methods=['GET'])
def data_entry():
    try:
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        
        return render_template('data_entry.html',user=user_info)
    except Exception as e:
        return f"Template rendering failed: {e}"

#CODE FOR GETTING POLICIES TO FORM
@app.route('/data-entry', methods=['GET'])
def data_entry_form():
    
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT policy_id, policy_name FROM policy_input WHERE status = 'Active'")
    policies = cursor.fetchall()
    conn.close()
    return render_template('data_entry.html', policies=policies)
#CODE FOR GETTING POLICIES TO FORM ENDS

@app.route('/submit-data', methods=['POST'])
def submit_data():
       
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    data = {
        'hospital_id' : request.form.get('hospital_id'),
        'name': request.form.get('name'),
        'age': request.form.get('age'),
        'gender': request.form.get('gender'),
        'dob': request.form.get('dob'),
        'contact_info': request.form.get('contact_info'),
        'weight': request.form.get('weight'),
        'height': request.form.get('height'),
        'blood_pressure': request.form.get('bp'),
        'temperature': request.form.get('temperature'),
        'blood_sugar': request.form.get('blood_sugar'),
        'department': request.form.get('department'),
        'doctor': request.form.get('doctor'),
        'disease': request.form.get('disease'),
        'lab_reports': request.form.get('lab_reports'),
        'policy_involvement': request.form.get('policy-involvement'),
        'policy_schema': request.form.get('policy-schema-input'),
        'past_illness': request.form.get('past-illness'),
        'allergies': request.form.get('allergies'),
        'previous_treatments': request.form.get('previous-treatments'),
        'family_history': request.form.get('family-history'),
        'admission_date': request.form.get('admission_date'),
        'discharge_date': request.form.get('discharge_date')
    }

    cursor.execute("SELECT 1 FROM hospitals WHERE hospital_id = ?", (data['hospital_id'],))
    hospital_exists = cursor.fetchone()

    if not hospital_exists:
        conn.close()
        return "❌ Invalid hospital ID. Hospital does not exist.", 400

    # Insert into patients (for latest info)
    cursor.execute('''
        INSERT INTO patients (
            hospital_id, name, age, gender, dob, contact_info,
            weight, height, blood_pressure, temperature, blood_sugar,
            department, doctor, disease, lab_reports,
            policy_involvement, policy_schema,
            past_illness, allergies, previous_treatments, family_history,
            admission_date, discharge_date
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    ''', (
        data['hospital_id'], data['name'], data['age'], data['gender'], data['dob'], data['contact_info'],
        data['weight'], data['height'], data['blood_pressure'], data['temperature'], data['blood_sugar'],
        data['department'], data['doctor'], data['disease'], data['lab_reports'],
        data['policy_involvement'], data['policy_schema'],
        data['past_illness'], data['allergies'], data['previous_treatments'], data['family_history'],
        data['admission_date'], data['discharge_date']
    ))

    # Also Insert into admissions (history purpose)
    cursor.execute('''
        INSERT INTO admissions (
            hospital_id, name, age, gender, dob, contact_info,
            weight, height, blood_pressure, temperature, blood_sugar,
            department, doctor, disease, lab_reports,
            policy_involvement, policy_schema,
            past_illness, allergies, previous_treatments, family_history,
            admission_date, discharge_date
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    ''', (
        data['hospital_id'], data['name'], data['age'], data['gender'], data['dob'], data['contact_info'],
        data['weight'], data['height'], data['blood_pressure'], data['temperature'], data['blood_sugar'],
        data['department'], data['doctor'], data['disease'], data['lab_reports'],
        data['policy_involvement'], data['policy_schema'],
        data['past_illness'], data['allergies'], data['previous_treatments'], data['family_history'],
        data['admission_date'], data['discharge_date']
    ))

    conn.commit()
    conn.close()
    flash("Patient data submitted successfully!")
    return redirect(url_for('data_entry'))



@app.route('/update_data',methods=['GET'])
def update_data():
    if 'user_id' not in session:
        flash("You must log in first", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line
    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "hospital_id": user["hospital_id"]
        }
    else:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))

    return render_template('update_data.html',user=user_info)

#CODE FOR UPDATING PATIENT DATA
def get_db_connection():
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    return conn

# Fetch patient details
@app.route('/fetch_patient/<int:reg_id>')
def fetch_patient(reg_id):

    logged_in_hosp_id = session['hospital_id']
    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (reg_id,)).fetchone()
    conn.close()

    if patient is None:
        return jsonify({'error': 'Invalid Patient ID'}), 404
    if patient['hospital_id'] != logged_in_hosp_id:
        return jsonify({'error': "Access denied. Patient doesn't belong to your hospital."}), 403
    return jsonify({
        'patient_id': patient['patient_id'],
        'name': patient['name'],
        'age': patient['age'],
        'gender': patient['gender'],
        'dob': patient['dob'],
        'contact_info': patient['contact_info'],
        'weight': patient['weight'],
        'height': patient['height'],
        'blood_pressure': patient['blood_pressure'],
        'temperature': patient['temperature'],
        'blood_sugar': patient['blood_sugar'],
        'department': patient['department'],
        'doctor': patient['doctor'],
        'disease': patient['disease'],
        'lab_reports': patient['lab_reports'],
        'policy_involvement': patient['policy_involvement'],
        'policy_schema': patient['policy_schema'],
        'past_illness': patient['past_illness'],
        'allergies': patient['allergies'],
        'previous_treatments': patient['previous_treatments'],
        'family_history': patient['family_history'],
        'admission_date': patient['admission_date'],
        'discharge_date': patient['discharge_date'],
        'hospital_id': patient['hospital_id']
    })

@app.route('/update_patient', methods=['GET', 'POST'])
def update_patient():
    if 'user_id' not in session:
        flash("You must log in first", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line
    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "hospital_id": user["hospital_id"]
        }
    else:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))
    patient_id = request.form['patient_id']

    updated_data = {
        'hospital_id': request.form['hospital_id'],
        'name': request.form['name'],
        'age': request.form['age'],
        'gender': request.form['gender'],
        'dob': request.form['dob'],
        'contact_info': request.form['contact_info'],
        'weight': request.form['weight'],
        'height': request.form['height'],
        'blood_pressure': request.form['blood_pressure'],
        'temperature': request.form['temperature'],
        'blood_sugar': request.form['blood_sugar'],
        'department': request.form['department'],
        'doctor': request.form['doctor'],
        'disease': request.form['disease'],
        'lab_reports': request.form['lab_reports'],
        'policy_involvement': request.form['policy_involvement'],
        'policy_schema': request.form['policy_schema'],
        'past_illness': request.form['past_illness'],
        'allergies': request.form['allergies'],
        'previous_treatments': request.form['previous_treatments'],
        'family_history': request.form['family_history'],
        'admission_date': request.form['admission_date'],
        'discharge_date': request.form['discharge_date']
    }

    conn = sqlite3.connect('db/hdims.db')
    cursor = conn.cursor()

    # Update latest patient record
    cursor.execute("""
        UPDATE patients
        SET
            hospital_id = ?, name = ?, age = ?, gender = ?, dob = ?, contact_info = ?, weight = ?, height = ?,
            blood_pressure = ?, temperature = ?, blood_sugar = ?, department = ?, doctor = ?, disease = ?, 
            lab_reports = ?, policy_involvement = ?, policy_schema = ?, past_illness = ?, allergies = ?,
            previous_treatments = ?, family_history = ?, admission_date = ?, discharge_date = ?
        WHERE patient_id = ?
    """, (
        updated_data['hospital_id'], updated_data['name'], updated_data['age'], updated_data['gender'], updated_data['dob'],
        updated_data['contact_info'], updated_data['weight'], updated_data['height'], updated_data['blood_pressure'],
        updated_data['temperature'], updated_data['blood_sugar'], updated_data['department'], updated_data['doctor'],
        updated_data['disease'], updated_data['lab_reports'], updated_data['policy_involvement'], updated_data['policy_schema'],
        updated_data['past_illness'], updated_data['allergies'], updated_data['previous_treatments'], updated_data['family_history'],
        updated_data['admission_date'], updated_data['discharge_date'], patient_id
    ))

    # Insert a fresh row into admissions table
    cursor.execute('''
        INSERT INTO admissions (
            patient_id, hospital_id, name, age, gender, dob, contact_info,
            weight, height, blood_pressure, temperature, blood_sugar,
            department, doctor, disease, lab_reports,
            policy_involvement, policy_schema,
            past_illness, allergies, previous_treatments, family_history,
            admission_date, discharge_date
        ) VALUES (
            ? ,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    ''', (
        patient_id ,updated_data['hospital_id'], updated_data['name'], updated_data['age'], updated_data['gender'], updated_data['dob'],
        updated_data['contact_info'], updated_data['weight'], updated_data['height'], updated_data['blood_pressure'],
        updated_data['temperature'], updated_data['blood_sugar'], updated_data['department'], updated_data['doctor'],
        updated_data['disease'], updated_data['lab_reports'], updated_data['policy_involvement'], updated_data['policy_schema'],
        updated_data['past_illness'], updated_data['allergies'], updated_data['previous_treatments'], updated_data['family_history'],
        updated_data['admission_date'], updated_data['discharge_date']
    ))

    conn.commit()
    conn.close()
    

    source_page = request.form.get('source_page')

    flash("Patient data updated successfully!")
    
    if source_page == 'update_data':
        return redirect(url_for('update_data'))
    elif source_page == 'update_data_dept':
        return redirect(url_for('update_data_dept'))
    else:
        return "Unknown source", 400

    


'''@app.route('/update_success')
def update_success():
    return "Patient data updated successfully!"'''


#CODE FOR UPDATING PATIENT DATA ENDS

@app.route('/program_entry')
def program_entry():
    if 'user_id' not in session:
        flash("You must log in first", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line
    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "hospital_id": user["hospital_id"]
        }
    else:
        conn.close()
        flash("User not found", "error")
        return redirect(url_for('login'))
    return render_template('program_entry.html',user=user_info)

# Data entries submitted by hospitals
class DataEntry(db.Model):
    __tablename__ = 'data_entries'
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.hospital_id'), nullable=False)
    program_name = db.Column(db.String(100), nullable=False)
    program_id = db.Column(db.Integer, db.ForeignKey('policy_inputs.id'),nullable=False)
    start_date = db.Column(db.String(50), nullable=False)
    proposed_end_date = db.Column(db.String(50), nullable=False)
    actual_end_date = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False)
    people_participated = db.Column(db.Integer, nullable=True)
    delayed = db.Column(db.String(10), nullable=False)
    delay_reason = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=True)
    current_data = db.Column(db.String(50), nullable=True)
#DATA BASE CREATION ENDS

#CODE FOR SUBMITTING PROGRM ENTRY DATA
@app.route('/program-data', methods=['GET', 'POST'])
def program_data():
    form_data = {
        'hospital_id': '',
        'program_id': '',
        'program_name': '',
        'start_date': '',
        'proposed_end_date': '',
        'actual_end_date': '',
        'people_participated': '',
        'delayed': '',
        'delay_reason': '',
        'updated_by': '',
        'department': '',
        'current_data':''
    }
    if request.method == 'POST':
        # 1. Grab raw inputs
        hosp_id_raw    = request.form.get('hospital_id')
        prog_id_raw    = request.form.get('program_id')
        program_name   = request.form.get('program_name')
        start_date     = request.form.get('start_date')
        proposed_end   = request.form.get('proposed_end_date')
        actual_end     = request.form.get('actual_end_date')
        people_part    = request.form.get('people_participated')
        delayed        = request.form.get('delayed')
        delay_reason   = request.form.get('delay_reason') if delayed == 'Yes' else None
        updated_by     = request.form.get('updated_by')
        department = request.form.get('department')
        current_data=request.form.get('current_data')

        form_data.update({
            'hospital_id': hosp_id_raw,
            'program_id': prog_id_raw,
            'program_name': program_name,
            'start_date': start_date,
            'proposed_end_date': proposed_end,
            'actual_end_date': actual_end,
            'people_participated': people_part,
            'delayed': delayed,
            'delay_reason': delay_reason,
            'updated_by': updated_by,
            'department': department,
            'current_data':current_data
        })
        # 2. Validate Hospital ID format & existence
        try:
            hospital_id = int(hosp_id_raw)
        except (TypeError, ValueError):
            flash("❌ Invalid Hospital ID format.", "error")
            return redirect(url_for('program_entry'))

        if not Hospital.query.filter_by(hospital_id=hospital_id).first():
            flash("❌ Hospital ID does not exist.", "error")
            return redirect(url_for('program_entry'))

        # 3. Validate Program ID format & existence
        try:
            program_id = int(prog_id_raw)
        except (TypeError, ValueError):
            flash("❌ Invalid Program ID format.", "error")
            return redirect(url_for('program_entry'))

        # Check in policy_inputs table
        conn = sqlite3.connect("db/hdims.db")
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM policy_inputs WHERE id = ?", (program_id,))
        if not cursor.fetchone():
            conn.close()
            flash("❌ Program ID does not exist. Please enter a valid one.", "error")
            return redirect(url_for('program_entry'))
        conn.close()
        if delayed == 'Yes' and not delay_reason:
            flash("❌ Please specify the reason for the delay.", "error")
            return redirect(url_for('program_entry'))

        # 4. All checks passed → create entry
        entry = DataEntry(
            hospital_id         = hospital_id,
            program_name        = program_name,
            program_id          = (program_id),  
            start_date          = start_date,
            proposed_end_date   = proposed_end,
            actual_end_date     = actual_end,
            status              = "In Progress" if delayed == "No" else "Delayed",
            people_participated = int(people_part),
            delayed             = delayed,
            delay_reason        = delay_reason,
            updated_by          = updated_by,
            department= department,
            current_data=current_data
        )
        db.session.add(entry)
        db.session.commit()
        print("✅ Entry committed to database!")
        print(f"Hospital ID: {hospital_id}, Program Name: {program_name}")
        flash("✅ Program entry submitted successfully!", "success")
        return redirect(url_for('program_entry'))

    # GET → render form
    return render_template("program_entry.html")
#PROGRAM ENTRY DATA SUBMISSION CODE COMPLETES

'''if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)'''

#TO REFLECT THE PROGRAM ENTRY IN SUPERADMIN DASHBOARD
@app.route('/get_program_announcements', methods=['GET'])
def get_program_announcements():
    # 1. Build a subquery that, for each program_name, finds the max(id)
    subq = (
        db.session.query(
            DataEntry.program_name.label('program_name'),
            func.max(DataEntry.id).label('latest_id')
        )
        .group_by(DataEntry.program_name)
        .subquery()
    )

    # 2. Query the subquery, ordering by latest_id desc, and limit to 10
    results = (
        db.session.query(subq.c.program_name)
        .order_by(subq.c.latest_id.desc())
        .limit(10)
        .all()
    )

    # 3. Build JSON response
    announcement_data = [{'title': name} for (name,) in results]
    return jsonify(announcement_data)

#THE CODE TO SHOWS ANNOUNCMENT IN SUPERADMIN ENDS HERE 
@app.route('/get_hospital_details/<int:hospital_id>', methods=['GET'])
def get_hospital_details(hospital_id):
    # Query the database for the hospital details based on the ID
    hospital = Hospital.query.get(hospital_id)  # Example query
    if hospital:
        return jsonify({
            "name": hospital.name,
            "location": hospital.location,
            "contact": hospital.contact,
            "status": hospital.status
        })
    else:
        return jsonify({"error": "Hospital not found"}), 404

#CODE FOR hospital names displaying in superadmin dashboard

#code ends for displaying superadmin dashboard hospital naes 
# OTP Generation and Verification
@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')
    user = User.query.filter_by(email=email, role='superadmin').first()
    
    if not user:
        return jsonify({'success': False, 'message': 'Email not registered as superadmin'})
    
    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.now() + timedelta(minutes=5)  # OTP valid for 5 minutes
    
    # Store OTP
    otp_storage[email] = {
        'otp': otp,
        'expiry': otp_expiry
    }
    
    # Send Email
    try:
        msg = MIMEText(f'Your HDIMS SuperAdmin OTP is: {otp}\nThis OTP is valid for 5 minutes.')
        msg['Subject'] = 'Your HDIMS SuperAdmin Login OTP'
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = email
        
        with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)

        
        return jsonify({'success': True, 'message': 'OTP sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send OTP: {str(e)}'})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email')
    otp_attempt = request.json.get('otp')

    stored_otp = otp_storage.get(email)

    if not stored_otp:
        return jsonify({'success': False, 'message': 'OTP not found or expired'})

    if datetime.now() > stored_otp['expiry']:
        return jsonify({'success': False, 'message': 'OTP expired'})

    if otp_attempt == stored_otp['otp']:
        # OTP is valid
        del otp_storage[email]  # Remove used OTP

        # ✅ Step 1: Get user from DB
        conn = sqlite3.connect('db/hdims.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, role FROM user WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id, role = user

            # ✅ Step 2: Set session
            session['user_id'] = user_id
            session['role'] = role

            # ✅ Step 3: Redirect based on role
            if role == 'superadmin':
                return jsonify({'success': True, 'redirect': url_for('superadmin_dashboard')})
            elif role == 'hospitaladmin':
                return jsonify({'success': True, 'redirect': url_for('hospital_dashboard')})
            elif role == 'departmentstaff':
                return jsonify({'success': True, 'redirect': url_for('department_dashboard')})
            else:
                return jsonify({'success': False, 'message': 'Invalid role'})
        else:
            return jsonify({'success': False, 'message': 'User not found'})

    else:
        return jsonify({'success': False, 'message': 'Invalid OTP'})


'''@app.route('/super_dsh')
def super_dsh():
    return render_template('superadmin_dsh.html')'''

from flask import request, render_template
import sqlite3
from datetime import date

@app.route('/view', methods=['GET', 'POST'])
def view():
    print("View route is being accessed!")

    try:
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))

        today = date.today().strftime('%Y-%m-%d')
        print(f"Today's date: {today}")

        # Fetch hospitals
        cursor.execute('SELECT DISTINCT name FROM hospitals')
        hospitals = [row[0] for row in cursor.fetchall()]
        print("Hospitals:", hospitals)

        # Fetch departments
        cursor.execute('SELECT DISTINCT department FROM patients')
        departments = [row[0] for row in cursor.fetchall()]
        print("Departments:", departments)

        # Overview Stats
        cursor.execute('SELECT COUNT(*) FROM patients WHERE discharge_date IS NULL')
        total_treated = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM patients WHERE discharge_date IS NOT NULL')
        total_discharged = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM patients')
        total_patients = cursor.fetchone()[0]

        discharge_rate = (total_discharged / total_patients * 100) if total_patients != 0 else 0
        discharge_rate = round(discharge_rate, 2)

        cursor.execute('SELECT COUNT(*) FROM patients WHERE admission_date = ?', (today,))
        new_admissions = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*)
            FROM admissions a1
            WHERE a1.admission_date = ?
            AND EXISTS (
                SELECT 1
                FROM admissions a2
                WHERE a2.patient_id = a1.patient_id
                AND a2.admission_date < a1.admission_date
            )
        ''', (today,))
        readmissions = cursor.fetchone()[0]

        # ------- Handling Filters --------
        department_filter = request.form.get('department', 'all')
        hospital_filter = request.form.get('hospital', 'all')

        print("Selected department:", department_filter)
        print("Selected hospital:", hospital_filter)

        # Build query
        base_query = '''
            SELECT h.name as name, COUNT(p.patient_id) as patients_treated,
                   ROUND(SUM(CASE WHEN p.discharge_date IS NOT NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(p.patient_id), 2) as discharge_rate,
                   SUM(CASE WHEN p.admission_date = ? THEN 1 ELSE 0 END) as new_admissions,
                   0 as readmissions   -- Placeholder
            FROM patients p
            JOIN hospitals h ON p.hospital_id = h.hospital_id
        '''
        filters = []
        params = [today]

        if department_filter != 'all':
            filters.append('p.department = ?')
            params.append(department_filter)

        if hospital_filter != 'all':
            filters.append('h.name = ?')
            params.append(hospital_filter)

        if filters:
            base_query += ' WHERE ' + ' AND '.join(filters)

        base_query += ' GROUP BY h.name'

        print("Executing Performance Query...")
        cursor.execute(base_query, params)
        rows = cursor.fetchall()

        performance_data = []
        for row in rows:
            performance_data.append({
                'name': row[0],
                'patients_treated': row[1],
                'discharge_rate': row[2],
                'new_admissions': row[3],
                'readmissions': row[4]  # You can calculate readmissions properly later
            })

        print("Performance Data:", performance_data)

        conn.close()
        print("Database connection closed.")

        return render_template('view.html',
                               hospitals=hospitals,
                               departments=departments,
                               total_treated=total_treated,
                               discharge_rate=discharge_rate,
                               new_admissions=new_admissions,
                               readmissions=readmissions,
                               performance_data=performance_data,user=user_info)
    
    except Exception as e:
        print(f"Error: {e}")
        return "Error occurred!"
    
class PolicyInput(db.Model):
    __tablename__ = 'policy_inputs'
    id = db.Column(db.Integer, primary_key=True)
    program_name = db.Column(db.String, nullable=False)
    proposed_date = db.Column(db.String)
    start_date = db.Column(db.String)
    end_date = db.Column(db.String)
    description = db.Column(db.String)
    key_area = db.Column(db.String)
    department = db.Column(db.String)

@app.route('/get_allergies')
def get_allergies():
    import sqlite3
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT allergies FROM patients WHERE allergies IS NOT NULL")
    rows = cursor.fetchall()
    conn.close()  # ✅ Good practice to close connection

    allergy_list = [row['allergies'] for row in rows if row['allergies']]
    return jsonify(allergy_list)

'''@app.route('/generat', methods=['GET', 'POST'])
def generat():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        cursor.execute("SELECT DISTINCT department FROM patients WHERE department IS NOT NULL")
        departments = [row[0] for row in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT name FROM hospitals")
        hospitals = [row[0] for row in cursor.fetchall()]
        # Get unique delay reasons from admissions or data_entries if that's where it exists
        cursor.execute("SELECT DISTINCT delay_reason FROM data_entries WHERE delay_reason IS NOT NULL")
        delay_reasons = [row[0] for row in cursor.fetchall()]
        
        # Get unique diseases
        cursor.execute("SELECT DISTINCT disease FROM patients WHERE disease IS NOT NULL AND disease != '' ORDER BY disease")
        diseases = [row[0] for row in cursor.fetchall()]
        
        return render_template('generat.html',
                            user=user_info,
                            departments=departments,
                            delay_reasons=delay_reasons,
                            hospitals=hospitals,
                            diseases=diseases)  # Add diseases to template context

JOIN_CONDITIONS = {
    'patients': "JOIN patients ON admissions.patient_id = patients.patient_id",
    'data_entries': "LEFT JOIN data_entries ON admissions.policy_involvement = data_entries.policy_involvement",
    'policy_inputs': "LEFT JOIN policy_inputs ON admissions.policy_involvement = policy_inputs.program_name",
    'hospitals': "LEFT JOIN hospitals ON admissions.hospital_id = hospitals.hospital_id"
}
TABLE_PRIORITY = ['admissions', 'patients', 'data_entries', 'hospitals', 'policy_inputs']'''

@app.route('/generat', methods=['GET', 'POST'])
def generat():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        cursor.execute("SELECT DISTINCT department FROM patients WHERE department IS NOT NULL")
        departments = [row[0] for row in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT name FROM hospitals")
        hospitals = [row[0] for row in cursor.fetchall()]
        # Get unique delay reasons from admissions or data_entries if that's where it exists
        cursor.execute("SELECT DISTINCT delay_reason FROM data_entries WHERE delay_reason IS NOT NULL")
        delay_reasons = [row[0] for row in cursor.fetchall()]
        
        # Get unique diseases
        cursor.execute("SELECT DISTINCT disease FROM patients WHERE disease IS NOT NULL AND disease != '' ORDER BY disease")
        diseases = [row[0] for row in cursor.fetchall()]
        
        return render_template('generat.html',
                            user=user_info,
                            departments=departments,
                            delay_reasons=delay_reasons,
                            hospitals=hospitals,
                            diseases=diseases)  # Add diseases to template context

JOIN_CONDITIONS = {
    'patients': "JOIN patients ON admissions.patient_id = patients.patient_id",
    'data_entries': "LEFT JOIN data_entries ON admissions.policy_involvement = data_entries.policy_involvement",
    'policy_inputs': "LEFT JOIN policy_inputs ON admissions.policy_involvement = policy_inputs.program_name",
    'hospitals': "LEFT JOIN hospitals ON admissions.hospital_id = hospitals.hospital_id"
}
TABLE_PRIORITY = ['admissions', 'patients', 'data_entries', 'hospitals', 'policy_inputs']

@app.route('/generat_data', methods=['POST'])
def generat_data():
    try:
        data = request.json
        x_axis = data.get('x_axis')
        y_axis = data.get('y_axis')
        filters = data.get('filters', {})

        x_config = FIELD_CONFIG.get(x_axis)
        y_config = FIELD_CONFIG.get(y_axis)
        if not x_config or not y_config:
            return jsonify({"error": "Invalid axis parameters."}), 400

        # Special handling for blood sugar levels with categorical x-axis
        if y_axis == 'blood_sugar' and x_axis in ['department', 'disease', 'gender', 'allergies']:
            x_table = FIELD_TABLE_MAP[x_axis]
            y_table = FIELD_TABLE_MAP[y_axis]
            
            # Define blood sugar ranges
            ranges = [
                (0, 70, 'Low (<70)'),
                (70, 100, 'Normal (70-100)'),
                (100, 125, 'Pre-diabetic (100-125)'),
                (125, 1000, 'Diabetic (>125)')  # Using 1000 instead of inf
            ]
            
            # Build the query
            select_fields = []
            group_fields = []
            
            # X-axis selection
            x_expr = f"{x_table}.{x_axis}"
            select_fields.append(f"{x_expr} as x")
            group_fields.append(x_expr)
            
            # Add range-based counts
            range_cases = []
            for min_val, max_val, label in ranges:
                case = f"SUM(CASE WHEN {y_table}.{y_axis} >= {min_val} AND {y_table}.{y_axis} < {max_val} THEN 1 ELSE 0 END) as '{label}'"
                range_cases.append(case)
            
            select_fields.extend(range_cases)
            
            # Add median calculation
            select_fields.append(f"ROUND(AVG({y_table}.{y_axis}), 2) as median_value")
            
            select_clause = ", ".join(select_fields)
            group_clause = ", ".join(group_fields)
            
            # Build FROM clause
            from_clause = f"FROM {x_table}"
            if x_table != y_table:
                from_clause += f" JOIN {y_table} ON {x_table}.hospital_id = {y_table}.hospital_id"
            
            # Build WHERE clause
            where_clauses, params = build_filter_clauses(filters)
            where_clause = ""
            if where_clauses:
                where_clause = "WHERE " + " AND ".join(where_clauses)
            
            # Add condition to exclude NULL or empty values
            if where_clause:
                where_clause += " AND "
            else:
                where_clause = "WHERE "
            where_clause += f"{x_table}.{x_axis} IS NOT NULL AND {x_table}.{x_axis} != '' AND {y_table}.{y_axis} IS NOT NULL"
            
            # Final query
            sql = f"SELECT {select_clause} {from_clause} {where_clause} GROUP BY {group_clause} ORDER BY median_value DESC"
            result = db.session.execute(text(sql), params).fetchall()
            
            # Process results
            x_labels = []
            datasets = []
            range_labels = [label for _, _, label in ranges]
            
            for row in result:
                x_labels.append(str(row.x))
                for label in range_labels:
                    if label not in [ds['label'] for ds in datasets]:
                        datasets.append({
                            'label': label,
                            'data': []
                        })
                    datasets[range_labels.index(label)]['data'].append(getattr(row, label))
            
            if not x_labels:  # If no data found
                return jsonify({
                    "error": "No data found for the selected parameters"
                }), 404
            
            return jsonify({
                "chart_type": "bar",
                "data": {
                    "labels": x_labels,
                    "datasets": datasets
                },
                "x_label": x_axis.replace('_', ' ').title(),
                "y_label": "Number of Patients by Blood Sugar Range"
            })

        # Special handling for blood pressure with categorical x-axis
        if y_axis == 'blood_pressure' and x_axis in ['department', 'disease', 'gender', 'allergies', 'age']:
            x_table = FIELD_TABLE_MAP[x_axis]
            y_table = FIELD_TABLE_MAP[y_axis]
            
            # Define blood pressure ranges for both systolic and diastolic
            systolic_ranges = [
                (0, 90, 'Low (<90)'),
                (90, 120, 'Normal (90-120)'),
                (120, 140, 'Elevated (120-140)'),
                (140, 1000, 'High (>140)')
            ]
            
            diastolic_ranges = [
                (0, 60, 'Low (<60)'),
                (60, 80, 'Normal (60-80)'),
                (80, 90, 'Elevated (80-90)'),
                (90, 1000, 'High (>90)')
            ]
            
            # Build the query
            select_fields = []
            group_fields = []
            
            # X-axis selection
            x_expr = f"{x_table}.{x_axis}"
            select_fields.append(f"{x_expr} as x")
            group_fields.append(x_expr)
            
            # Add range-based counts for systolic
            for min_val, max_val, label in systolic_ranges:
                case = f"SUM(CASE WHEN CAST(SUBSTR({y_table}.{y_axis}, 1, INSTR({y_table}.{y_axis}, '/')-1) AS INTEGER) >= {min_val} AND CAST(SUBSTR({y_table}.{y_axis}, 1, INSTR({y_table}.{y_axis}, '/')-1) AS INTEGER) < {max_val} THEN 1 ELSE 0 END) as 'Systolic {label}'"
                select_fields.append(case)
            
            # Add range-based counts for diastolic
            for min_val, max_val, label in diastolic_ranges:
                case = f"SUM(CASE WHEN CAST(SUBSTR({y_table}.{y_axis}, INSTR({y_table}.{y_axis}, '/')+1) AS INTEGER) >= {min_val} AND CAST(SUBSTR({y_table}.{y_axis}, INSTR({y_table}.{y_axis}, '/')+1) AS INTEGER) < {max_val} THEN 1 ELSE 0 END) as 'Diastolic {label}'"
                select_fields.append(case)
            
            # Add average calculations
            select_fields.append(f"ROUND(AVG(CAST(SUBSTR({y_table}.{y_axis}, 1, INSTR({y_table}.{y_axis}, '/')-1) AS INTEGER)), 2) as avg_systolic")
            select_fields.append(f"ROUND(AVG(CAST(SUBSTR({y_table}.{y_axis}, INSTR({y_table}.{y_axis}, '/')+1) AS INTEGER)), 2) as avg_diastolic")
            
            select_clause = ", ".join(select_fields)
            group_clause = ", ".join(group_fields)
            
            # Build FROM clause
            from_clause = f"FROM {x_table}"
            if x_table != y_table:
                from_clause += f" JOIN {y_table} ON {x_table}.hospital_id = {y_table}.hospital_id"
            
            # Build WHERE clause
            where_clauses, params = build_filter_clauses(filters)
            where_clause = ""
            if where_clauses:
                where_clause = "WHERE " + " AND ".join(where_clauses)
            
            # Add condition to exclude NULL or empty values
            if where_clause:
                where_clause += " AND "
            else:
                where_clause = "WHERE "
            where_clause += f"{x_table}.{x_axis} IS NOT NULL AND {x_table}.{x_axis} != '' AND {y_table}.{y_axis} IS NOT NULL AND {y_table}.{y_axis} != ''"
            
            # Final query
            sql = f"SELECT {select_clause} {from_clause} {where_clause} GROUP BY {group_clause} ORDER BY avg_systolic DESC"
            result = db.session.execute(text(sql), params).fetchall()
            
            # Process results
            x_labels = []
            datasets = []
            range_labels = [f"Systolic {label}" for _, _, label in systolic_ranges] + [f"Diastolic {label}" for _, _, label in diastolic_ranges]
            
            for row in result:
                x_labels.append(str(row.x))
                for label in range_labels:
                    if label not in [ds['label'] for ds in datasets]:
                        datasets.append({
                            'label': label,
                            'data': []
                        })
                    datasets[range_labels.index(label)]['data'].append(getattr(row, label))
            
            if not x_labels:  # If no data found
                return jsonify({
                    "error": "No data found for the selected parameters"
                }), 404
            
            return jsonify({
                "chart_type": "bar",
                "data": {
                    "labels": x_labels,
                    "datasets": datasets
                },
                "x_label": x_axis.replace('_', ' ').title(),
                "y_label": "Number of Patients by Blood Pressure Range"
            })

        # Special handling for age as y-axis (keep existing code)
        if y_axis == 'age':
            x_table = FIELD_TABLE_MAP[x_axis]
            y_table = FIELD_TABLE_MAP[y_axis]
            
            # Build base query for counting ages
            select_fields = []
            group_fields = []
            
            # X-axis selection
            if x_axis == 'recovery_time':
                x_expr = "julianday(admissions.discharge_date) - julianday(admissions.admission_date)"
                group_by = x_expr
            else:
                x_expr = f"{x_table}.{x_axis}"
                group_by = f"{x_table}.{x_axis}"
            
            select_fields.append(f"{x_expr} as x")
            group_fields.append(group_by)
            
            # For age, we'll count occurrences
            select_fields.append("COUNT(*) as count")
            
            select_clause = ", ".join(select_fields)
            group_clause = ", ".join(group_fields)
            
            # Build FROM clause
            from_clause = f"FROM {x_table}"
            if x_table != y_table:
                from_clause += f" JOIN {y_table} ON {x_table}.hospital_id = {y_table}.hospital_id"
            
            # Build WHERE clause
            where_clauses, params = build_filter_clauses(filters)
            where_clause = ""
            if where_clauses:
                where_clause = "WHERE " + " AND ".join(where_clauses)
            
            # Add condition to exclude NULL or empty values for specific fields
            if x_axis in ['allergies', 'department', 'disease', 'gender']:
                if where_clause:
                    where_clause += " AND "
                else:
                    where_clause = "WHERE "
                where_clause += f"{x_table}.{x_axis} IS NOT NULL AND {x_table}.{x_axis} != ''"
            
            # Final query
            sql = f"SELECT {select_clause} {from_clause} {where_clause} GROUP BY {group_clause} ORDER BY count DESC"  # Order by count to show most common first
            result = db.session.execute(text(sql), params).fetchall()
            
            # Process results
            x_labels = []
            values = []
            for row in result:
                x_val = str(row.x)
                if x_val:  # Only include non-empty values
                    x_labels.append(x_val)
                    values.append(row.count)
            
            if not x_labels:  # If no data found
                return jsonify({
                    "error": "No data found for the selected parameters"
                }), 404
            
            return jsonify({
                "chart_type": "bar",  # Using bar chart for better visualization of counts
                "data": {
                    "labels": x_labels,
                    "values": values
                },
                "x_label": x_axis.replace('_', ' ').title(),
                "y_label": "Number of Patients"
            })

        # --- 1. Determine binning for numeric X ---
        x_table = FIELD_TABLE_MAP[x_axis]
        y_table = FIELD_TABLE_MAP[y_axis]
        binning = False
        bin_size = 1
        # --- Define base expressions ---
        if x_axis == 'recovery_time':
            x_expr = "julianday(admissions.discharge_date) - julianday(admissions.admission_date)"
            group_by = x_expr
        else:
            x_expr = f"{x_table}.{x_axis}"
            group_by = f"{x_table}.{x_axis}"
        if y_axis == 'recovery_time':
            y_expr = "julianday(admissions.discharge_date) - julianday(admissions.admission_date)"
        else:
            y_expr = f"{y_table}.{y_axis}"
        if x_config['type'] == 'numeric':
            # Count unique values in the filtered data
            where_clauses, params = build_filter_clauses(filters)
            count_query = f"SELECT COUNT(DISTINCT {x_table}.{x_axis}) FROM {x_table}"
            if where_clauses:
                count_query += " WHERE " + " AND ".join(where_clauses)
            unique_count = db.session.execute(text(count_query), params).scalar()
            if unique_count > 20:
                binning = True
                # Choose bin size (e.g., 10 bins)
                min_query = f"SELECT MIN({x_table}.{x_axis}) FROM {x_table}"
                max_query = f"SELECT MAX({x_table}.{x_axis}) FROM {x_table}"
                if where_clauses:
                    min_query += " WHERE " + " AND ".join(where_clauses)
                    max_query += " WHERE " + " AND ".join(where_clauses)
                min_val = db.session.execute(text(min_query), params).scalar() or 0
                max_val = db.session.execute(text(max_query), params).scalar() or 1
                bin_count = 10
                bin_size = max(1, int((max_val - min_val) / bin_count))
                x_expr = f"(({x_table}.{x_axis} - {min_val}) / {bin_size})"
                group_by = x_expr

        # --- 2. Build SELECT and GROUP BY ---
        select_fields = []
        group_fields = []
        select_fields.append(f"{x_expr} as x")
        group_fields.append(group_by)

        # Handle y-axis based on its type
        if y_config['type'] == 'numeric':
            # For numeric y-axis, calculate average
            select_fields.append(f"AVG({y_table}.{y_axis}) as y")
        elif y_config['type'] == 'categorical':
            select_fields.append(f"{y_table}.{y_axis} as y_group")
            group_fields.append(f"{y_table}.{y_axis}")

        select_fields.append("COUNT(*) as count")
        select_clause = ", ".join(select_fields)
        group_clause = ", ".join(group_fields)

        # --- 3. Build FROM and WHERE ---
        '''from_clause = f"FROM {x_table}"
        if x_table != y_table:
            # For your schema, join on hospital_id if both tables have it
            if ('hospital_id' in [col for col in ['hospital_id', 'patient_id'] if col in x_axis or col in y_axis]):
                from_clause += f" JOIN {y_table} ON {x_table}.hospital_id = {y_table}.hospital_id"
            else:
                return jsonify({'error': 'No valid join key between selected tables.'}), 400'''
        # --- 3. Build FROM, JOINs, and WHERE ---
        tables = {x_table, y_table}
        join_clauses = []
        from_clause = f"FROM {x_table}"

       # --- 3. Build FROM, JOINs, and WHERE ---
        if x_table == y_table:
            from_clause = f"FROM {x_table}"
        else:
            # Handle joins based on your schema relations
            if {x_table, y_table} == {'patients', 'data_entries'}:
                # Join both via hospitals table
                from_clause = (
                    f"FROM patients "
                    f"JOIN hospitals ON patients.hospital_id = hospitals.hospital_id "
                    f"JOIN data_entries ON data_entries.hospital_id = hospitals.hospital_id"
                )
            elif {x_table, y_table} == {'data_entries', 'policy_inputs'}:
                # Join on program_id -> policy_inputs.id
                if x_table == 'data_entries':
                    from_clause = (
                        f"FROM data_entries "
                        f"JOIN policy_inputs ON data_entries.program_id = policy_inputs.id"
                    )
                else:
                    from_clause = (
                        f"FROM policy_inputs "
                        f"JOIN data_entries ON data_entries.program_id = policy_inputs.id"
                    )
            else:
                return jsonify({'error': 'No valid join key between selected tables.'}), 400

        where_clauses, params = build_filter_clauses(filters)
        where_clause = ""
        if where_clauses:
            where_clause = "WHERE " + " AND ".join(where_clauses)

        # --- 4. Final Query ---
        sql = f"SELECT {select_clause} {from_clause} {where_clause} GROUP BY {group_clause} ORDER BY {group_clause}"
        result = db.session.execute(text(sql), params).fetchall()

        # --- 5. Process Results for Frontend ---
        if y_config['type'] == 'categorical':
            # Grouped bar: {x, y_group, count}
            data = {}
            x_labels = set()
            y_labels = set()
            for row in result:
                x_val = int(row.x) if x_config['type'] == 'numeric' else str(row.x)
                if binning:
                    x_val = f"{int(row.x)*bin_size + min_val}-{int(row.x)*bin_size + min_val + bin_size - 1}"
                y_val = str(row.y_group)
                x_labels.add(x_val)
                y_labels.add(y_val)
                data.setdefault(y_val, {})[x_val] = row.count
            # Prepare datasets for Chart.js
            datasets = []
            x_labels = sorted(list(x_labels), key=lambda v: int(v.split('-')[0]) if '-' in v else v)
            y_labels = sorted(list(y_labels))
            for y in y_labels:
                datasets.append({
                    'label': y,
                    'data': [data[y].get(x, 0) for x in x_labels]
                })
            return jsonify({
                "chart_type": "bar",
                "data": {
                    "labels": x_labels,
                    "datasets": datasets
                },
                "x_label": x_axis.replace('_', ' ').title(),
                "y_label": "Count"
            })
        else:
            # For numeric y-axis (like blood sugar), show average values
            x_labels = []
            values = []
            counts = []
            for row in result:
                x_val = int(row.x) if x_config['type'] == 'numeric' else str(row.x)
                if binning:
                    x_val = f"{int(row.x)*bin_size + min_val}-{int(row.x)*bin_size + min_val + bin_size - 1}"
                x_labels.append(x_val)
                values.append(round(float(row.y), 2))  # Round to 2 decimal places
                counts.append(row.count)
            return jsonify({
                "chart_type": "line",  # Changed to line chart for better visualization of trends
                "data": {
                    "labels": x_labels,
                    "values": values,
                    "counts": counts  # Include counts for reference
                },
                "x_label": x_axis.replace('_', ' ').title(),
                "y_label": f"Average {y_axis.replace('_', ' ').title()}"
            })

    except Exception as e:
        print(f"Error generating chart data: {str(e)}")
        return jsonify({"error": f"Failed to generate chart data: {str(e)}"}), 500

def build_base_query(x_axis, y_axis, x_config, y_config):
    """Build the base SQL query based on selected parameters."""
    try:
        x_table = FIELD_TABLE_MAP[x_axis]
        y_table = FIELD_TABLE_MAP[y_axis]
        
        # Start with the main table
        query = f"SELECT {x_table}.{x_axis} as x"
        
        # Add Y axis selection with appropriate aggregation
        if y_config['type'] == 'numeric':
            query += f", {y_config['aggregation']}({y_table}.{y_axis}) as y"
        elif y_config['type'] == 'categorical':
            # For categorical data, we'll count occurrences
            query += f", COUNT({y_table}.{y_axis}) as y"
        else:
            query += f", {y_table}.{y_axis} as y"
        
        # Add table joins
        query += f" FROM {x_table}"
        if x_table != y_table:
            # Custom join for patients <-> data_entries
            if (x_table == 'patients' and y_table == 'data_entries') or (x_table == 'data_entries' and y_table == 'patients'):
                query += " JOIN data_entries ON patients.policy_involvement = data_entries.program_name"
            # Use hospital_id if both have it
            elif 'hospital_id' in [x_axis, y_axis]:
                query += f" JOIN {y_table} ON {x_table}.hospital_id = {y_table}.hospital_id"
            else:
                raise Exception('No valid join key between selected tables.')
        
        # Add GROUP BY clause
        if x_config['type'] == 'categorical':
            query += f" GROUP BY {x_table}.{x_axis}"
            query += f" ORDER BY {x_table}.{x_axis}"
        elif x_config['type'] == 'numeric':
            query += f" GROUP BY {x_table}.{x_axis}"
            query += f" ORDER BY {x_table}.{x_axis}"
        
        return query
    except Exception as e:
        print(f"Error building query: {str(e)}")
        raise

def build_filter_clauses(filters):
    """Build WHERE clauses for filters."""
    where_clauses = []
    params = {}
    
    for field, value in filters.items():
        if not value:
            continue
            
        table = FIELD_TABLE_MAP.get(field)
        if not table:
            continue
            
        if isinstance(value, dict):
            # Handle range filters
            if 'min' in value and value['min']:
                where_clauses.append(f"{table}.{field} >= :{field}_min")
                params[f"{field}_min"] = value['min']
            if 'max' in value and value['max']:
                where_clauses.append(f"{table}.{field} <= :{field}_max")
                params[f"{field}_max"] = value['max']
        else:
            # Handle exact match filters
            where_clauses.append(f"{table}.{field} = :{field}")
            params[field] = value
    
    return where_clauses, params

def get_order_clause(field, field_type):
    """Get appropriate ORDER BY clause based on field type."""
    if field_type == 'date':
        return f"{FIELD_TABLE_MAP[field]}.{field} ASC"
    elif field_type == 'numeric':
        return f"y DESC"
    else:
        return f"{FIELD_TABLE_MAP[field]}.{field} ASC"

def process_chart_data(result, x_axis, y_axis, chart_type):
    """Process query results into chart data format."""
    try:
        # Check if we have range-based data (e.g., age ranges)
        has_range_data = any('min_' in str(row.x) or 'max_' in str(row.x) for row in result)
        
        if has_range_data:
            # Process range-based data into distribution points
            distribution = []
            for row in result:
                try:
                    x_value = float(row.x)
                    y_value = float(row.y)
                    distribution.append({
                        'x': x_value,
                        'y': y_value
                    })
                except (ValueError, TypeError):
                    continue
            
            return {
                'distribution': distribution
            }
        elif chart_type == 'pie':
            return [{'label': str(row.x), 'value': float(row.y)} for row in result]
        else:
            # Handle both numeric and categorical data
            labels = []
            values = []
            for row in result:
                labels.append(str(row.x))
                try:
                    # Try to convert to float, if fails use the value as is
                    values.append(float(row.y))
                except (ValueError, TypeError):
                    values.append(row.y)
            
            return {
                'labels': labels,
                'values': values
            }
    except Exception as e:
        print(f"Error processing chart data: {str(e)}")
        raise


def get_join_clauses(x_table, y_table):
    join_clauses = []
    tables = set([x_table, y_table])
    
    if x_table == y_table:
        return join_clauses, tables

    # Special: patients <-> data_entries via hospitals
    if ('hospital_id' in FIELD_TABLE_MAP.get(x_table, '') and
        'hospital_id' in FIELD_TABLE_MAP.get(y_table, '')):
        join_clauses.append(f"{x_table}.hospital_id = hospitals.hospital_id")
        join_clauses.append(f"{y_table}.hospital_id = hospitals.hospital_id")
        tables.add('hospitals')
        return join_clauses, tables

    # Special: data_entries -> policy_inputs via program_id
    if (x_table == 'data_entries' and y_table == 'policy_inputs'):
        join_clauses.append("data_entries.program_id = policy_inputs.id")
        return join_clauses, tables
    if (y_table == 'data_entries' and x_table == 'policy_inputs'):
        join_clauses.append("policy_inputs.id = data_entries.program_id")
        return join_clauses, tables

    # Fallback
    return None, None
@app.route('/monitor')
def monitor():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        # Fetch all programs with hospital info
        all_programs = db.session.query(
            DataEntry,
            Hospital.name  # Use 'name' instead of 'hospital_name'
        ).join(
            Hospital, DataEntry.hospital_id == Hospital.hospital_id
        ).all()

        under_implementation = []
        delayed_programs = []

        # Separate based on status
        for data_entry, hospital_name in all_programs:
            program_info = {
                'program_name': data_entry.program_name,
                'start_date': data_entry.start_date,
                'proposed_end_date': data_entry.proposed_end_date,
                'actual_end_date': data_entry.actual_end_date,
                'people_participated': data_entry.people_participated,
                'hospital_id': data_entry.hospital_id,
                'hospital_name': hospital_name,  # Still keep this key as 'hospital_name' for clarity
                'updated_by': data_entry.updated_by,
                'delayed': data_entry.delayed,
                'delay_reason': data_entry.delay_reason,
                'status': data_entry.status,
                'current_data':data_entry.current_data
            }

            if data_entry.status == "In Progress":
                under_implementation.append(program_info)
            elif data_entry.status == "Delayed":
                delayed_programs.append(program_info)

        return render_template('monitor.html',
                            under_implementation=under_implementation,
                            delayed_programs=delayed_programs,user=user_info)

'''@app.route('/policy', methods=['GET', 'POST'])
def policy():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        return render_template('policy.html',user=user_info)'''

def create_policy_input_table():
    conn = sqlite3.connect('db/hdims.db')  # adjust path if needed
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_inputs (
            id INTEGER PRIMARY KEY,
            program_name TEXT NOT NULL,
            proposed_date TEXT,
            start_date TEXT,
            end_date TEXT,
            description TEXT,
            key_area TEXT,
            department TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Call this once at the start of your app (inside if __name__ == '__main__')

@app.route('/policy_data', methods=['GET', 'POST'])
def policy_data():
    if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    user_id = session.get('user_id')
    print("User ID from session:", user_id)  # Debug line
    cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    print("User query result:", user)  # Debug line

    if user:
        user_info = {
                "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "hospital_id": user["hospital_id"]
                }
    else:
                conn.close()
                flash("User not found", "error")
                return redirect(url_for('login'))
    
    if request.method == 'POST':
        program_number = request.form['program_number']
        program_name = request.form['program_name']
        proposed_date = request.form['proposed_date']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        description = request.form['description']
        key_area = request.form['key_area']
        department=request.form['department']

        try:
            with sqlite3.connect('db/hdims.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO policy_inputs (id, program_name, proposed_date, start_date, end_date, description, key_area,department)
                    VALUES (?, ?, ?, ?, ?, ?, ?,?)
                ''', (program_number, program_name, proposed_date, start_date, end_date, description, key_area,department))
                conn.commit()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                return "Error: The database is currently locked. Please try again shortly."
            else:
                return f"Database Error: {str(e)}"

        return render_template('policy.html', success=True,user=user_info)

    return render_template('policy.html',user=user_info)

def get_all_users():
    conn = sqlite3.connect('db/hdims.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    conn.close()
    return users

# Route: Manage User Page
@app.route('/manage_user')
def manage_user():
        if 'user_id' not in session:
            flash("You must log in first", "error")
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('db/hdims.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Debug line
        cursor.execute("SELECT id, username, email, role, hospital_id FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print("User query result:", user)  # Debug line

        if user:
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "hospital_id": user["hospital_id"]
            }
        else:
            conn.close()
            flash("User not found", "error")
            return redirect(url_for('login'))
        users = get_all_users()
        return render_template('manage_user.html', users=users,user=user_info)

def delete_user_by_id(user_id):
    import sqlite3
    conn = sqlite3.connect('db/hdims.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # You need to implement delete_user_by_id() to delete user from DB
    delete_user_by_id(user_id)
    return redirect(url_for('manage_user'))

@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    hospital_id = request.form.get('hospital_id') or None  # Convert empty to None

    # Basic validations can be added here if needed
    conn = sqlite3.connect('db/hdims.db')
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE user
        SET username = ?, email = ?, role = ?, hospital_id = ?
        WHERE id = ?
    """, (username, email, role, hospital_id, user_id))
    conn.commit()
    conn.close()

    flash("User updated successfully", "success")
    return redirect(url_for('manage_user'))

@app.route('/api/diseases', methods=['GET'])
def get_diseases():
    try:
        conn = sqlite3.connect('db/hdims.db')
        cursor = conn.cursor()
        
        # Get unique diseases, excluding NULL and empty values
        cursor.execute('''
            SELECT DISTINCT disease 
            FROM patients 
            WHERE disease IS NOT NULL 
            AND disease != ''
            ORDER BY disease
        ''')
        
        diseases = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return jsonify(diseases)
    except Exception as e:
        print(f"Error fetching diseases: {str(e)}")
        return jsonify({"error": "Failed to fetch diseases"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()                 # Setup DB tables once
        create_centralized_db()        # Your custom function
        create_policy_input_table()    # Another setup function
    app.run(debug=True)

