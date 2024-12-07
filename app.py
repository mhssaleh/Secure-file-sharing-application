from flask import Flask, render_template, redirect, url_for, flash, session, request, send_file
from werkzeug.utils import secure_filename
from extensions import db, bcrypt
from forms import RegistrationForm, LoginForm
from models import User
from cryptography.fernet import Fernet, InvalidToken
import os
import io

# Function to load or generate the encryption key
def load_or_generate_key():
    key_file = "encryption_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as keyfile:
            return keyfile.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as keyfile:
            keyfile.write(key)
        return key

# Load or generate the encryption key
encryption_key = load_or_generate_key()
cipher = Fernet(encryption_key)

def create_app():
    app = Flask(__name__)
    
    # App configuration
    app.config['SECRET_KEY'] = 'bf1283bf2fed0a3bad5a7d9f9b9c608244820541336441e096ce8c8b5e1b236e'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/secure_file_sharing'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)

    # Home route
    @app.route('/')
    def home():
        return render_template('home.html')

    # Dashboard route
    @app.route('/dashboard')
    def dashboard():
        if not session.get('logged_in'):
            flash('Please log in to access the dashboard.', 'danger')
            return redirect(url_for('login'))
        
        if session.pop('just_logged_in', False):  # Only flash if just logged in
            flash('Login successful!', 'success')
        
        return render_template('dashboard.html')

    # Registration route
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            try:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                new_user = User(username=form.username.data, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                if "Duplicate entry" in str(e):
                    flash('Username is already taken. Please choose another.', 'danger')
                else:
                    flash(f'An error occurred: {e}', 'danger')

        return render_template('register.html', form=form)

    # Login route
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                session['logged_in'] = True
                session['username'] = user.username
                session['just_logged_in'] = True  # Mark as just logged in
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials. Please register first.', 'danger')
                return redirect(url_for('register'))
        return render_template('login.html', form=form)

    # Logout route
    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('home'))

    # File Upload Route
    @app.route('/upload', methods=['GET', 'POST'])
    def upload_file():
        if not session.get('logged_in'):
            flash('Please log in to upload files.', 'danger')
            return redirect(url_for('login'))

        if request.method == 'POST':
            file = request.files['file']
            if file:
                filename = secure_filename(file.filename)
                file_data = file.read()

                # Encrypt file data
                encrypted_data = cipher.encrypt(file_data)
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"encrypted_{filename}")

                # Save the encrypted file
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_data)

                flash(f'File "{filename}" uploaded and encrypted successfully!', 'success')
                return redirect(url_for('dashboard'))
        
        return render_template('upload.html')

    # File Listing Route
    @app.route('/files')
    def list_files():
        if not session.get('logged_in'):
            flash('Please log in to view files.', 'danger')
            return redirect(url_for('login'))

        # List all encrypted files in the uploads folder
        files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.startswith("encrypted_")]
        return render_template('files.html', files=files)

    # File Download Route
    @app.route('/download/<filename>')
    def download_file(filename):
        if not session.get('logged_in'):
            flash('Please log in to download files.', 'danger')
            return redirect(url_for('login'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(file_path):
            flash('File not found.', 'danger')
            return redirect(url_for('list_files'))

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
            
            decrypted_filename = filename.replace("encrypted_", "")
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=decrypted_filename
            )
        except InvalidToken:
            flash('The file could not be decrypted. It may have been tampered with.', 'danger')
            return redirect(url_for('list_files'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
