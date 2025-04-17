from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import config
from wtforms.fields import DateField, TimeField  # Оновлений імпорт

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'

# Налаштування підключення до бази даних PostgreSQL
conn = psycopg2.connect(
    dbname=config.DB_NAME,
    user=config.DB_USER,
    password=config.DB_PASSWORD,
    host=config.DB_HOST,
    port=config.DB_PORT
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, email, username, password_hash):
        self.id = id
        self.email = email
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if user:
            return User(*user)
        return None

    @staticmethod
    def find_by_email(email):
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user:
            return User(*user)
        return None

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.find_by_email(email.data)
        if user:
            raise ValidationError('That email is already taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class ConferenceForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    time = TimeField('Time', format='%H:%M', validators=[DataRequired()])
    speakers = TextAreaField('Speakers', validators=[DataRequired()])
    video_link = StringField('Video Link', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/')
def home():
    cur = conn.cursor()
    cur.execute("SELECT * FROM conferences")
    conferences = cur.fetchall()
    cur.close()
    return render_template('home.html', conferences=conferences)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                    (form.email.data, form.username.data, password_hash))
        conn.commit()
        cur.close()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    cur = conn.cursor()
    cur.execute("SELECT * FROM conferences WHERE user_id = %s", (current_user.id,))
    conferences = cur.fetchall()
    cur.close()
    return render_template('dashboard.html', conferences=conferences)


@app.route('/create_conference', methods=['GET', 'POST'])
@login_required
def create_conference():
    form = ConferenceForm()
    if form.validate_on_submit():
        cur = conn.cursor()
        cur.execute("INSERT INTO conferences (title, description, date, time, speakers, video_link, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (form.title.data, form.description.data, form.date.data, form.time.data, form.speakers.data, form.video_link.data, current_user.id))
        conn.commit()
        cur.close()
        flash('Conference created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_conference.html', form=form)


@app.route('/edit_conference/<int:conference_id>', methods=['GET', 'POST'])
@login_required
def edit_conference(conference_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM conferences WHERE id = %s AND user_id = %s", (conference_id, current_user.id))
    conference = cur.fetchone()
    if not conference:
        flash('Conference not found or not authorized', 'danger')
        return redirect(url_for('dashboard'))
    form = ConferenceForm()
    if form.validate_on_submit():
        cur.execute("UPDATE conferences SET title = %s, description = %s, date = %s, time = %s, speakers = %s, video_link = %s WHERE id = %s",
                    (form.title.data, form.description.data, form.date.data, form.time.data, form.speakers.data, form.video_link.data, conference_id))
        conn.commit()
        cur.close()
        flash('Conference updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.title.data = conference[1]
        form.description.data = conference[2]
        form.date.data = conference[4]
        form.time.data = conference[5]
        form.speakers.data = conference[6]
        form.video_link.data = conference[7]
    return render_template('edit_conference.html', form=form)


@app.route('/delete_conference/<int:conference_id>', methods=['POST'])
@login_required
def delete_conference(conference_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM conferences WHERE id = %s AND user_id = %s", (conference_id, current_user.id))
    conference = cur.fetchone()
    if not conference:
        flash('Conference not found or not authorized', 'danger')
        return redirect(url_for('dashboard'))
    cur.execute("DELETE FROM conferences WHERE id = %s", (conference_id,))
    conn.commit()
    cur.close()
    flash('Conference deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/conference/<int:conference_id>')
def view_conference(conference_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM conferences WHERE id = %s", (conference_id,))
    conference = cur.fetchone()
    cur.close()
    if not conference:
        flash('Conference not found', 'danger')
        return redirect(url_for('home'))
    return render_template('view_conference.html', conference=conference)


if __name__ == '__main__':
    app.run(debug=True)
