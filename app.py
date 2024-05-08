# Packages imports
from flask import Flask, render_template, redirect, url_for, request, flash, abort, session as flask_session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_admin import Admin
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from wtforms import PasswordField
from flask_admin.contrib.sqla import ModelView
from flask_admin.form.upload import FileUploadField
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os

load_dotenv()  # Загружает переменные окружения из файла .env

"""
Configurations
"""
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
static_url = os.getenv('STATIC_URL')
app_port = os.getenv('PORT')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 16800
database = SQLAlchemy(app)
login_manager = LoginManager(app)


"""
Tools
"""


def generate_csrf_token():
    csrf_token = flask_session.get('_csrf_token', None)
    if csrf_token is None:
        csrf_token = str(os.urandom(24))
        flask_session['_csrf_token'] = csrf_token
    return csrf_token


"""
Models
"""


class User(database.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False)
    password = Column(String(150), nullable=False)
    mail = Column(String(150), nullable=True, default='')
    is_admin = Column(Boolean, default=False)

    def __repr__(self):
        return f'{self.username}'

    def is_authenticated(self):
        return self.id is not None

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


class Course(database.Model):
    __tablename__ = 'course'
    id = Column(Integer, primary_key=True)
    course_name = Column(String(80), unique=True, nullable=False)
    description = Column(String(200), nullable=False)
    price = Column(Integer, nullable=False)
    video = Column(String(200), nullable=True)

    def __repr__(self):
        return f'{self.course_name}'


class CourseAccess(database.Model):
    __tablename__ = 'course_access'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    course_id = Column(Integer, ForeignKey('course.id'), nullable=False)
    months = Column(Integer, nullable=False)
    start_date = Column(DateTime, nullable=False, default=datetime.now)
    end_date = Column(DateTime, nullable=False)

    user = relationship("User", backref="course_accesses")
    course = relationship("Course", backref="user_accesses")


"""
Admin
"""


class UserView(ModelView):
    column_list = ('id', 'username', 'mail', 'is_admin')
    form_columns = ('username', 'password', 'mail', 'is_admin')
    column_searchable_list = ('username', 'mail')
    column_filters = ('is_admin',)
    form_extra_fields = {
        'password': PasswordField('Password')
    }


class CourseView(ModelView):
    column_list = ('id', 'course_name', 'description', 'price')
    column_searchable_list = ('course_name', 'description')
    column_filters = ('price',)

    form_overrides = {
        'video': FileUploadField
    }

    form_args = {
        'video': {
            'label': 'Video',
            'base_path': os.path.join(static_url, 'static', 'videos'),
            'allow_overwrite': True
        }
    }


class CourseAccessView(ModelView):
    column_list = ('id', 'user.username', 'course.course_name',
                   'months', 'start_date', 'end_date')
    form_columns = ('user', 'course', 'months', 'start_date')
    column_searchable_list = ('user.username', 'course.course_name')
    column_filters = ('months', 'start_date', 'end_date')

    form_ajax_refs = {
        'user': {
            'fields': (User.username,),
            'page_size': 10
        },
        'course': {
            'fields': (Course.course_name,),
            'page_size': 10
        }
    }

    def on_model_change(self, form, model, is_created):
        if not form.user.data or not form.course.data:
            flash('User or course not specified correctly.', 'error')
            return False

        if form.start_date.data and form.months.data:
            model.end_date = form.start_date.data + \
                timedelta(days=30 * form.months.data)
        else:
            flash('Start date or months are not specified.', 'error')
            return False

        return True


admin = Admin(app, name='Admin Panel', template_mode='bootstrap4', base_template='admin/custom_adm_nav.html')
admin.add_view(UserView(User, database.session))
admin.add_view(CourseView(Course, database.session))
admin.add_view(CourseAccessView(CourseAccess, database.session))


"""
Middleware
"""


@app.before_request
def restrict_admin_access():
    if request.path.startswith('/admin'):
        if not current_user.is_authenticated or not current_user.is_admin:
            return abort(403)


@app.context_processor
def inject_current_user():
    return dict(current_user=current_user)


"""
Routing
"""


@app.route('/')
def main_page():
    return render_template('main_page.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    csrf_token = generate_csrf_token()
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'csrf_token' not in request.form or request.form['csrf_token'] != flask_session.get('_csrf_token', None):
            return abort(403)

        new_username = request.form.get('username')
        new_password = request.form.get('password')
        new_mail = request.form.get('mail')

        new_username_is_valid = len(new_username) > 6
        new_password_is_valid = not new_password or len(new_password) > 6

        data_is_valid = False

        if new_username_is_valid and new_password_is_valid:
            if current_user.username != new_username:
                username_exists = User.query.filter(
                    User.username == new_username).limit(1).first()
                if not username_exists:
                    data_is_valid = True
                else:
                    flash('A user with the same name already exists.', 'error')
            else:
                data_is_valid = True
        else:
            flash('Username and password must be at least 6 characters long', 'error')

        if data_is_valid:
            user = User.query.get(current_user.id)
            user.username = new_username
            user.mail = new_mail
            if new_password:
                user.password = generate_password_hash(
                    new_password, method='pbkdf2:sha256')
            database.session.commit()
            flash('Data has been changed', 'success')

    total_courses = Course.query.count()
    bought_courses = CourseAccess.query.filter_by(
        user_id=current_user.id).count()
    bought_percentage = (bought_courses / total_courses *
                         100) if total_courses > 0 else 0

    return render_template(
        'profile.html',
        username=current_user.username,
        mail=current_user.mail,
        csrf_token=csrf_token,
        bought_percentage=bought_percentage
    )


@app.route('/courses')
@app.route('/courses/<int:course_id>')
def courses(course_id=None):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if course_id:
        course = Course.query.get_or_404(course_id)
        return render_template('course_detail.html', course=course)

    bought_courses = CourseAccess.query.filter_by(
        user_id=current_user.id).all()
    bought_course_ids = [access.course_id for access in bought_courses]

    all_courses = Course.query.filter(Course.id.notin_(
        bought_course_ids)).all() if bought_course_ids else Course.query.all()

    return render_template('courses.html', all_courses=all_courses, bought_courses=bought_courses)


@app.route('/courses/<int:course_id>/watch')
def watch_course(course_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    course_access = CourseAccess.query.filter_by(
        user_id=current_user.id, course_id=course_id).first()
    if not course_access or course_access.end_date < datetime.utcnow():
        abort(403)
    course = Course.query.get_or_404(course_id)
    return render_template('watch_video.html', course=course)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    csrf_token = generate_csrf_token()
    if request.method == 'POST':
        if 'csrf_token' not in request.form or request.form['csrf_token'] != flask_session.get('_csrf_token', None):
            return abort(403)

        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_admin = password.startswith(os.getenv('ADMIN_KEY'))

        if len(username) < 6 or len(password) < 6:
            flash('Password and username must be at least 6 characters long', 'error')
            return redirect(url_for('registration'))

        if password != confirm_password:
            flash('Password mismatch.', 'error')
            return redirect(url_for('registration'))

        existing_user = User.query.filter(
            User.username == username).limit(1).first()
        if existing_user:
            flash('A user with the same name already exists.', 'error')
            return redirect(url_for('registration'))

        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256')

        new_user = User(username=username,
                        password=hashed_password, is_admin=is_admin)

        database.session.add(new_user)
        database.session.commit()

        flash('You have successfully registered. You can log in.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html', csrf_token=csrf_token)


@app.route('/login', methods=['GET', 'POST'])
def login():
    csrf_token = generate_csrf_token()
    if request.method == 'POST':
        if 'csrf_token' not in request.form or request.form['csrf_token'] != flask_session.get('_csrf_token', None):
            return abort(403)

        username = request.form['username']
        password = request.form['password']

        user = User.query.filter(User.username == username).limit(1).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('profile'))
            else:
                flash('Password mismatch.', 'error')
        else:
            flash('User is not found.', 'error')

    return render_template('login.html', csrf_token=csrf_token)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main_page'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    # database.create_all()
    with app.app_context():
        database.create_all()
    app.run(debug=True, port=app_port)
