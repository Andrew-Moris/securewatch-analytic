import csv
from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

failed_attempts = {}
failed_registrations = {}

def get_client_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            return response.json()['ip']
    except:
        pass
    
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
    return request.environ.get('REMOTE_ADDR', 'Unknown IP')

@app.route('/styles/<path:filename>')
def styles(filename):
    return send_from_directory('styles', filename)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client_ip = get_client_ip()

        with open('data\\Weblogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            if user and user.check_password(password):
                if username in failed_attempts:
                    del failed_attempts[username]
                login_user(user)
                writer.writerow([
                    "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                    f"Name: {username}\n"
                    f"Date Login: {login_time}\n"
                    f"IP Address: {client_ip}\n"
                    "Login Status: Successful\n"
                    "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                ])
                return redirect(url_for('dashboard'))
            else:
                process_type = "Not matched data" if user else "User not found"
                
                if user:
                    if username not in failed_attempts:
                        failed_attempts[username] = 1
                    else:
                        failed_attempts[username] += 1
                    
                    if failed_attempts[username] >= 3:
                        with open('data\\reports.txt', 'a') as report_file:
                            report_file.write(f"\nFailed Login Attempts Report\n")
                            report_file.write(f"Username: {username}\n")
                            report_file.write(f"Time: {login_time}\n")
                            report_file.write(f"IP Address: {client_ip}\n")
                            report_file.write(f"Status: Account locked due to 3 failed attempts with wrong password\n")
                            report_file.write(f"Process Type: {process_type}\n")
                            report_file.write("-" * 50 + "\n")
                        del failed_attempts[username]
                
                writer.writerow([
                    "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                    f"Name: {username}\n"
                    f"Date Login: {login_time}\n"
                    f"IP Address: {client_ip}\n"
                    "Login Status: Failed\n"
                    f"Process Type: {process_type}\n"
                    "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                ])
                flash('Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = get_client_ip()
    
    with open('data\\Weblogs.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if User.query.filter_by(username=username).first():
                if username not in failed_registrations:
                    failed_registrations[username] = 1
                else:
                    failed_registrations[username] += 1
                
                if failed_registrations[username] >= 3:
                    with open('data\\reports.txt', 'a') as report_file:
                        report_file.write(f"\nFailed Registration Attempts Report\n")
                        report_file.write(f"Username: {username}\n")
                        report_file.write(f"Time: {login_time}\n")
                        report_file.write(f"IP Address: {client_ip}\n")
                        report_file.write(f"Status: Registration up to 3 attempts username with wrong passwords\n")
                        report_file.write(f"Process Type: Account already exists and Not matched data\n")
                        report_file.write("-" * 50 + "\n")
                    del failed_registrations[username]
                
                writer.writerow([
                    "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                    f"Name: {username}\n"
                    f"Date Register: {login_time}\n"
                    f"IP Address: {client_ip}\n"
                    "Register Status: Failed\n"
                    "Process Type: Account already exists\n"
                    "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                ])
                flash('Username already exists')
                return redirect(url_for('register'))
            
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            writer.writerow([
                "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                f"Name: {username}\n"
                f"Date Register: {login_time}\n"
                f"IP Address: {client_ip}\n"
                "Register Status: Successful\n"
                "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            ])

            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        user = current_user
        username = user.username
        delete_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client_ip = get_client_ip()

        with open('data\\Weblogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
                f"Name: {username}\n"
                f"Date: {delete_time}\n"
                f"IP Address: {client_ip}\n"
                "Status: Account Deleted\n"
                "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            ])

        db.session.delete(user)
        db.session.commit()

        logout_user()

        return redirect(url_for('index'))
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = get_client_ip()  # Get client IP

    with open('data\\Weblogs.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            "\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            f"Name: {username}\n"
            f"Date: {logout_time}\n"
            f"IP Address: {client_ip}\n"
            "Status: Logout\n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
        ])

    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
