from flask import Flask, render_template, redirect, url_for, request, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
import random
import string
import io
import re
from sqlalchemy.exc import IntegrityError

# Configurações
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:admin@localhost:5432/dropslim')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limita a 16 MB

# Configuração do Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'calebewerneck@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'bmuw gyau wjrx xfly')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Inicializa extensões
db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'

# Modelos
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)
    department = db.relationship('Department', backref='members', lazy=True)  # Renomeado para 'members'

class Department(db.Model):
    __tablename__ = 'department'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='department_obj', lazy=True)

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)

class FileShare(db.Model):
    __tablename__ = 'file_share'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)

    file = db.relationship('File', backref='shared_with')
    user = db.relationship('User', backref='shared_files')
    department = db.relationship('Department', backref='shared_files')

# Função para carregar usuário
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas
@app.route('/')
def home():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    departments = Department.query.all()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        department_id = request.form['department_id']
        
        if User.query.filter_by(username=username).first():
            flash('Username já existe, escolha outro.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado, escolha outro.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, department_id=department_id)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Conta criada com sucesso! Você já pode fazer login.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro ao criar conta. Tente novamente.', 'danger')

    return render_template('register.html', departments=departments)

@app.route('/edit_department/<int:id>', methods=['POST'])
@login_required
def edit_department(id):
    department = Department.query.get_or_404(id)
    data = request.get_json()
    
    if 'name' in data:
        department.name = data['name']
        try:
            db.session.commit()
            return jsonify({'message': 'Department updated successfully!'}), 200
        except IntegrityError:
            db.session.rollback()
            return jsonify({'message': 'Error updating department.'}), 400
    
    return jsonify({'message': 'Invalid data!'}), 400

@app.route('/share_files', methods=['POST'])
@login_required
def share_files():
    file_id = request.form.get('file_id')
    user_id = request.form.get('user_id')
    department_id = request.form.get('department_id')

    if not file_id:
        flash("Você deve selecionar um arquivo para compartilhar.")
        return redirect(url_for('file_list'))

    file_to_share = File.query.get(file_id)
    if not file_to_share:
        flash("Arquivo não encontrado.", 'danger')
        return redirect(url_for('file_list'))

    existing_share = FileShare.query.filter_by(file_id=file_id, user_id=user_id, department_id=department_id).first()
    if existing_share:
        flash("Este arquivo já foi compartilhado com este usuário ou departamento.", 'warning')
        return redirect(url_for('file_list'))

    new_share = FileShare(file_id=file_id, user_id=user_id or None, department_id=department_id or None)
    db.session.add(new_share)
    try:
        db.session.commit()
        flash("Arquivo compartilhado com sucesso!")
    except IntegrityError:
        db.session.rollback()
        flash("Erro ao compartilhar arquivo. Tente novamente.", 'danger')

    return redirect(url_for('file_list'))

@app.route('/create_department', methods=['GET', 'POST'])
@login_required
def create_department():
    if request.method == 'POST':
        department_name = request.form['name'].upper()
        
        if Department.query.filter_by(name=department_name).first():
            flash('Departamento já existe.', 'danger')
            return redirect(url_for('create_department'))
        
        new_department = Department(name=department_name)
        db.session.add(new_department)
        try:
            db.session.commit()
            flash('Departamento criado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro ao criar departamento. Tente novamente.', 'danger')

    departments = Department.query.all()
    return render_template('create_department.html', departments=departments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login inválido. Verifique seu username e senha.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_name = current_user.username
    user_department = current_user.department.name  # Ajuste para acessar o nome do departamento
    files = File.query.filter_by(user_id=current_user.id).all()
    file_shares = FileShare.query.filter((FileShare.user_id == current_user.id) | (FileShare.department_id == current_user.department_id)).all()

    return render_template('dashboard.html', user_name=user_name, user_department=user_department, files=files, file_shares=file_shares)

@app.route('/file_list', methods=['GET'])
@login_required
def file_list():
    search_query = request.args.get('search', '')
    
    user_files = File.query.filter_by(user_id=current_user.id)
    shared_file_ids = FileShare.query.filter_by(user_id=current_user.id).with_entities(FileShare.file_id).all()
    shared_files = File.query.filter(File.id.in_([file_id[0] for file_id in shared_file_ids]))

    if search_query:
        user_files = user_files.filter(File.description.ilike(f'%{search_query}%'))
        shared_files = shared_files.filter(File.description.ilike(f'%{search_query}%'))

    all_files = user_files.union(shared_files).all()
    all_users = User.query.all()
    all_departments = Department.query.all()

    return render_template('file_list.html', files=all_files, all_users=all_users, all_departments=all_departments)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        description = request.form.get('description')

        if not file or file.filename == '':
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(request.url)

        original_filename = secure_filename(file.filename)
        clean_filename = re.sub(r'[^a-zA-Z0-9_.]', '_', original_filename)
        file_data = file.read()

        new_file = File(filename=clean_filename, user_id=current_user.id, data=file_data, description=description)
        db.session.add(new_file)
        try:
            db.session.commit()
            flash('Arquivo enviado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro ao enviar arquivo. Tente novamente.', 'danger')

    return render_template('upload.html')

@app.route('/file/<int:file_id>', methods=['GET'])
@login_required
def uploaded_file(file_id):
    file_to_send = File.query.get(file_id)
    if file_to_send:
        return send_file(
            io.BytesIO(file_to_send.data), 
            as_attachment=True, 
            download_name=file_to_send.filename
        )
    else:
        flash('Arquivo não encontrado.', 'danger')
        return redirect(url_for('file_list'))

@app.route('/delete_file/<int:file_share_id>', methods=['POST'])
@login_required
def delete_file(file_share_id):
    file_share = FileShare.query.get(file_share_id)

    if file_share:
        if file_share.user_id == current_user.id or current_user.department_id in [1, 2]:
            file_id = file_share.file_id
            db.session.delete(file_share)

            other_shares = FileShare.query.filter_by(file_id=file_id).count()

            if other_shares == 0:
                file_to_delete = File.query.get(file_id)
                if file_to_delete:
                    db.session.delete(file_to_delete)

            try:
                db.session.commit()
                flash("Compartilhamento e arquivo excluídos com sucesso." if other_shares == 0 else "Compartilhamento excluído com sucesso.", 'success')
            except IntegrityError:
                db.session.rollback()
                flash("Erro ao excluir o compartilhamento. Tente novamente.", 'danger')
        else:
            flash("Você não tem permissão para excluir este compartilhamento.", 'danger')
    else:
        file_to_delete = File.query.get(file_share_id)
        if file_to_delete:
            db.session.delete(file_to_delete)
            try:
                db.session.commit()
                flash("Arquivo excluído com sucesso.", 'success')
            except IntegrityError:
                db.session.rollback()
                flash("Erro ao excluir o arquivo. Tente novamente.", 'danger')
        else:
            flash("Arquivo não encontrado.", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/delete_department/<int:id>', methods=['POST'])
@login_required
def delete_department(id):
    department = Department.query.get_or_404(id)
    db.session.delete(department)
    try:
        db.session.commit()
        flash('Departamento excluído com sucesso!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Erro ao excluir departamento. Tente novamente.', 'danger')
    return redirect(url_for('create_department'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        if check_password_hash(current_user.password, current_password):
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Senha atual incorreta.', 'danger')
    
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

            user.password = hashed_password
            db.session.commit()

            msg = Message("Nova Senha", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Sua nova senha é: {new_password}\nPor favor, altere sua senha após fazer login."
            mail.send(msg)

            flash('Uma nova senha foi enviada para o seu email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email não encontrado.', 'danger')

    return render_template('forgot_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
