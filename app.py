from urllib.parse import quote_plus
from flask import Flask, render_template, url_for, redirect, abort, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum, ForeignKey, func
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import DateTimeField, SelectField,StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError, Email, EqualTo
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt 
from datetime import datetime
from sqlalchemy.sql import func
import os

app = Flask(__name__)

user= os.getenv('USER_RR')
password= os.getenv('PASSWORD_RR')
server= os.getenv('SERVER_RR')
db_name = os.getenv('DB_NAME_RR')
secret_key = os.getenv('SECRET_KEY_RR')
app.config['SECRET_KEY'] = secret_key


encoded_password = quote_plus(password)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{user}:{encoded_password}@{server}/{db_name}' 

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100))
    user_type = db.Column(Enum('regular', 'restaurant owner', 'administrator'), default='regular')
    state = db.Column(db.String(45), nullable=True)
    city = db.Column(db.String(45), nullable=True)
    street = db.Column(db.String(45), nullable=True)

class SignUpForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": 'name'})
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": 'email'})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=100)], render_kw={"placeholder": 'password'})
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')], render_kw={"placeholder": 'Confirm password'})
    state = StringField('State', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": 'state'})
    city = StringField('City', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": 'city'})
    street = StringField('Street', validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder": 'street'})
    submit = SubmitField('Sign Up')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": 'email'})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=100)], render_kw={"placeholder": 'password'})
    submit = SubmitField('Login')

class Restaurants(db.Model):
    __tablename__ = 'Restaurants'
    restaurant_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, ForeignKey('Users.id'), nullable=True)
    restaurant_name = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    opening_hours = db.Column(db.String(50), nullable=True)
    food_type = db.Column(db.String(45), nullable=True)
    state = db.Column(db.String(45), nullable=True)
    city = db.Column(db.String(45), nullable=True)
    street = db.Column(db.String(45), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    image_path_menu = db.Column(db.String(255), nullable=True)
    

class Reservations(db.Model):
    __tablename__ = 'Reservations'
    reservation_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, ForeignKey('Users.id'), nullable=True)
    restaurant_id = db.Column(db.Integer, ForeignKey('Restaurants.restaurant_id'), nullable=True)
    id_mesa = db.Column(db.Integer, ForeignKey('Mesas.id_mesa'), nullable=True)
    reservation_date_time = db.Column(db.DateTime, nullable=True)

class Mesas(db.Model):
    __tablename__ = 'Mesas'
    id_mesa = db.Column(db.Integer, primary_key=True, autoincrement= True)
    restaurant_id = db.Column(db.Integer, ForeignKey('Restaurants.restaurant_id'), nullable=True)
    capacity = db.Column(db.Integer, nullable = True)
    

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/how-to-use')
def how_to_use():
    return render_template('how-to-use.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email is already registered', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(name=form.name.data, email=form.email.data, password=hashed_password, state=form.state.data, city=form.city.data, street=form.street.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('dashboard'))
    return render_template('signup.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 12
    restaurants = Restaurants.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('dashboard.html', user=current_user, restaurants=restaurants.items, pagination=restaurants)


@app.route('/menus', methods = ['GET', 'POST'])
@login_required
def menus():
    page = request.args.get('page', 1, type=int)
    per_page = 6
    restaurants = Restaurants.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('menus.html', user=current_user, restaurants=restaurants, pagination=restaurants)

@app.route('/yourreservations')
@login_required
def yourreservations():
    user_id = current_user.id
    reservations = Reservations.query.filter_by(user_id=user_id).all()
    for reservation in reservations:
        reservation.restaurant = Restaurants.query.get(reservation.restaurant_id)
    return render_template('yourreservations.html', reservations=reservations)



class ReservationForm(FlaskForm):
    reservation_date_time = DateTimeField('Date and Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    id_mesa = SelectField('Table', validators=[DataRequired()])
    submit = SubmitField('Reserve')

@app.route('/restaurant/<int:restaurant_id>', methods=['GET', 'POST'])
def restaurant(restaurant_id):
    restaurant = Restaurants.query.get(restaurant_id)
    if restaurant is None:
        abort(404)
    user = User.query.get(restaurant.user_id)
    mesas = Mesas.query.filter_by(restaurant_id=restaurant_id).all()

    form = ReservationForm()
    form.id_mesa.choices = [(mesa.id_mesa, f'Table {mesa.id_mesa} (Capacity: {mesa.capacity})') for mesa in mesas]

    if form.validate_on_submit():
        reservation_date_time = form.reservation_date_time.data
        id_mesa = form.id_mesa.data

        existing_reservation = Reservations.query.filter_by(id_mesa=id_mesa, reservation_date_time=reservation_date_time).first()

        if existing_reservation:
            flash('The table is already booked for that date and time. Please choose another table or date/time.', 'danger')
            return redirect(url_for('restaurant', restaurant_id=restaurant_id))

        new_reservation = Reservations(
            user_id=current_user.id,
            restaurant_id=restaurant_id,
            reservation_date_time=reservation_date_time,
            id_mesa=id_mesa
        )
        db.session.add(new_reservation)
        db.session.commit()
        flash('Reservation made successfully.', 'success')
        return redirect(url_for('restaurant', restaurant_id=restaurant_id))

    return render_template('restaurant.html', restaurant=restaurant, user=user, mesas=mesas, form=form)


@app.route('/most_reserved_restaurant', methods=['GET'])
def most_reserved_restaurant():
    most_reserved_restaurant = db.session.query(
        Reservations.restaurant_id,
        func.count(Reservations.reservation_id).label('total_reservations')
    ).group_by(Reservations.restaurant_id).order_by(func.count(Reservations.reservation_id).desc()).first()

    if most_reserved_restaurant:
        return redirect(url_for('restaurant', restaurant_id=most_reserved_restaurant.restaurant_id))
    else:
        flash('No reservations found.')
        return redirect(url_for('dashboard'))



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

 

if __name__ == '__main__':
    app.run(debug=True)
