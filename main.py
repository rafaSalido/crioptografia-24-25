from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import json

from utils import allowed_file, get_user_files, load_json, save_json
from models import db, User
from encriptar import encrypt_file, decrypt_file, is_strong_password
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a strong secret key in production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


# Ensure uploads folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


JSON_FILE_PATH = 'files.json'



# Initialize the database
with app.app_context():
    db.init_app(app)
    db.create_all()

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('upload_page'))
    return redirect(url_for('login'))



""" AUTHENTICATION """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:  # In production, use proper password hashing
            session['username'] = username
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('upload_page'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')

        new_user = User(username=username, password=password)  # In production, hash the password
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



""" ENCRYPTION APP """
@app.get('/upload')
def upload_page():
    if 'username' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))
    
    user_files = get_user_files(JSON_FILE_PATH)
    return render_template('upload.html', files=user_files, username=session['username'])


@app.post('/upload')
def upload_file():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    # Obtain request variables
    file = request.files['file']
    password = request.form.get('password')
    user_id = session.get('user_id')
    
    #
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400

    if not is_strong_password(password):
        return jsonify({'error': 'Password must be at least 5 characters long'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    # Encrypt information
    try:
        # Extract and save file
        filename = secure_filename(file.filename)
        user_filename = f"user_{user_id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
        file.save(file_path)
            
        app.logger.info(f"File saved to: {file_path}")
        
        if not os.path.exists(file_path):
            return jsonify({'error': f'File not saved properly: {file_path}'}), 500
            
        # Encrypt the file uploaded
        encrypted_file_path = encrypt_file(file_path, password)
        if encrypted_file_path is None:
            raise Exception('Encryption failed')
            
        app.logger.info(f"File encrypted. New path: {encrypted_file_path}")
            
        # Delete the original file once is encrypted
        os.remove(file_path)
        app.logger.info(f"Original file removed: {file_path}")

        # Save and link to the respective user the file uploaded
        files_data = load_json(JSON_FILE_PATH)
        files_data['files'].append({
            "name": filename,
            "password": password,
            "path": encrypted_file_path,
            "user_id": user_id
         })
        save_json(files_data, JSON_FILE_PATH)
            
        return jsonify({
                'message': 'File encrypted and saved successfully',
                'filename': os.path.basename(encrypted_file_path)
            })

    except Exception as e:
        app.logger.error(f"Error in file upload: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.post('/download')
def download_file():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    print("Form: ", request.form.get('path'), " ", request.form.get('password'))

    path = request.form.get('path')
    password = request.form.get('password')
    user_id = session.get('user_id')

    if not all([path, password, user_id]):
        return jsonify({'error': 'Missing required information'}), 400
    
    if not os.path.exists(path):
        print("Filepath: ", path)
        return jsonify({'error': 'File not found'}), 404

    temp_decrypted = None
    try:
        # Attempt to decrypt the file
        temp_decrypted = decrypt_file(path, password)

        # Return the decrypted file as an attachment
        return send_file(
            temp_decrypted,
            as_attachment=True,
            download_name=path.replace('_encrypted', '').replace(f"user_{user_id}_", "")
        )
    
    except Exception as e:
        # Handle decryption errors
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
    
    finally:
        # Ensure the temporary file is always cleaned up after the request is handled
        if temp_decrypted and os.path.exists(temp_decrypted):
            os.remove(temp_decrypted)





if __name__ == '__main__':
    app.run(debug=True)