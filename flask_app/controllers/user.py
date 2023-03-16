from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_app.models.user_class import Users
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template("login_reg.html")

@app.route('/register', methods=['POST'])
def register_user():
    if not Users.validate_user(request.form):
        return redirect('/')
    user_data = {
        'first_name':request.form['first_name'],
        'last_name':request.form['last_name'],
        'email':request.form['email'],
        'password':bcrypt.generate_password_hash(request.form['password'])
    }
    user_id = Users.save(user_data)
    session['id'] = user_id
    return redirect('/welcome')

@app.route('/login',methods=['POST'])
def login():
    data = {
    'email': request.form['email']
    }
    user_in_DB = Users.get_user_by_email(data)
    if not user_in_DB:
        flash('Invalid email','login')
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_DB.password,request.form['password']):
        flash('Incorrect Password or Email, try again','login')
        return redirect('/')
    session['id'] = user_in_DB.id
    session['first_name'] = user_in_DB.first_name
    session['email'] = user_in_DB.email
    return redirect('/welcome')

@app.route('/welcome')
def welcome():
    if 'id' not in session:
        return redirect('/logout')
    data = {
        "id":session['id']
    }
    return render_template('welcome.html',user=Users.get_user_by_id(data))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')