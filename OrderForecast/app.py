from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, ValidationError, Length
from flask_bcrypt import Bcrypt

import numpy as np
import pickle

app = Flask(__name__)
# read our pickle file and label our logisticmodel as model
model = pickle.load(open(r'C:\Users\Lenovo\Downloads\Oasis_Store.pickle', 'rb'))

#
# @app.route('/')
# def home():
#     return render_template('home.html')
#

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    int_features = [float(x) for x in request.form.values()]
    final_features = [np.array(int_features)]
    prediction = model.predict(final_features)

    if prediction == 0:
        return render_template('home.html',
                               prediction_text='Low chances of patient having diabetes'.format(prediction),
                               )
    else:
        return render_template('home.html',
                               prediction_text='High chances of patient having diabetes'.format(prediction),
                               )


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'


# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField([InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exist. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField([InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
def hello():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


# @app.route('/dashboard', methods=['GET', 'POST'])
# @login_required
# def dashboard():
#     return render_template('dashboard.html')

#
# @app.route('/logout', methods=['GET', 'POST'])
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
