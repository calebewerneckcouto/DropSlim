from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, File, Department  # Importação absoluta
from forms import LoginForm, RecoverPasswordForm, DepartmentForm, UserForm, ChangePasswordForm

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', files=current_user.files)

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    form = RecoverPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            new_password = 'newpassword'  # Gera uma nova senha temporária
            user.password = generate_password_hash(new_password)
            db.session.commit()
            # Enviar email com a nova senha (implementação não incluída)
            flash('Password reset successful. Check your email.', 'success')
        else:
            flash('Email not found.', 'danger')
    return render_template('recover_password.html', form=form)

@app.route('/departments', methods=['GET', 'POST'])
@login_required
def departments():
    form = DepartmentForm()
    if form.validate_on_submit():
        new_department = Department(name=form.name.data)
        db.session.add(new_department)
        db.session.commit()
        flash('Department created successfully!', 'success')
        return redirect(url_for('departments'))
    
    departments = Department.query.all()
    return render_template('departments.html', form=form, departments=departments)

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    form = UserForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            department_id=form.department.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('users'))

    users = User.query.all()
    departments = Department.query.all()
    return render_template('users.html', form=form, users=users, departments=departments)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_password.data):
            current_user.password = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Old password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
