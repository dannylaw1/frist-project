from flask import Flask, render_template, flash,request,jsonify,redirect,url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField,BooleanField,ValidationError
from wtforms.validators import DataRequired ,Email,EqualTo,Length 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime,date
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin , login_user,logout_user,current_user,LoginManager,login_required


# Create a Flask instance
helloapp = Flask(__name__)
# Secret key
helloapp.config['SECRET_KEY'] = 'this is my secret key'

# # old Database
helloapp.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# New Database
# helloapp.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:mysql@localhost/our_users'

# Initialize the Database
db = SQLAlchemy(helloapp)
Migrate=Migrate(helloapp,db)


#Json Thing 
# @helloapp.route('/date')
# def current_date():
#     return jsonify({'Date': str(date.today())})

login_manager=LoginManager()
login_manager.init_app(helloapp)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return  Users.query.get(int(user_id))

#Login form 
class LoginForm(FlaskForm):
    username=StringField("Username",validators=[DataRequired()])  
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Submit")


# Login page
@helloapp.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			# Check the hash
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user)
				flash("Login Succesfull!!")
				return redirect(url_for('dashboard'))
			else:
				flash("Wrong Password - Try Again!")
		else:
			flash("That User Doesn't Exist! Try Again...")


	return render_template('login.html', form=form)

# Create Logout Page
@helloapp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out!  Thanks For Stopping By...")
	return redirect(url_for('login'))

# Create Dashboard Page
@helloapp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
     return render_template('dashboard.html')

	# form = UserForm()
	# id = current_user.id
	# name_to_update = Users.query.get_or_404(id)
	# if request.method == "POST":
	# 	name_to_update.name = request.form['name']
	# 	name_to_update.email = request.form['email']
	# 	name_to_update.favorite_color = request.form['favorite_color']
	# 	name_to_update.username = request.form['username']
	# 	name_to_update.about_author = request.form['about_author']


# Create Model 
class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username= db.Column(db.String(20), nullable=False,unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    favorite_color=db.Column(db.String(120))
    #Password
    password_hash=db.Column(db.String(120))
    @property
    def password(self):
        raise AttributeError('pasword is not a readable attribute!')
    @password.setter
    def password(self,password):
        self.password_hash=generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    # Create a String
    def __repr__(self):
        return "<Name %r>" % self.name

@helloapp.route('/delete/<id>', methods=['GET', 'POST'])
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    try:
        name = None
        form = UserForm()
        db.session.delete(user_to_delete)
        db.session.commit()  # Commit the changes to the database
        flash('User deleted successfully')
        our_users = Users.query.order_by(Users.date_added).all()
        return render_template('add_user.html', form=form, name=name, our_users=our_users)
    except:
        flash('User could not be deleted')
        our_users = Users.query.order_by(Users.date_added).all()
        return render_template('add_user.html', form=form, name=name, our_users=our_users)

         

# Create a Form Class
class UserForm(FlaskForm):
    name = StringField("Name:", validators=[DataRequired()])
    username= StringField('Username :',validators=[DataRequired()])
    email=StringField('Email:',validators=[DataRequired()])
    favorite_color=StringField('Favorite Color:')
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match')])
    password_hash2=PasswordField('Confirm password ',validators=[DataRequired()])
    submit = SubmitField('Submit')



# Update Database records 

@helloapp.route('/update/<int:id>',methods=['GET','POST'])
def update(id):
    form=UserForm()
    name_to_update=Users.query.get_or_404(id)
    if request.method=='POST':
        name_to_update.name= request.form['name']
        name_to_update.email= request.form['email']
        name_to_update.favorite_color= request.form['favorite_color']

        try:
            db.session.commit()
            flash('Error :User Updataed Successfully')
            return render_template('update.html',form=form, name_to_update=name_to_update)

        except:
            flash('user was not succefully update ')
            return render_template('update.html',form=form, name_to_update=name_to_update)
    else:
        return render_template('update.html',form=form, name_to_update=name_to_update,id=id)




# Create a Form Class
class NamerForm(FlaskForm):
    name = StringField("What's Your Name:", validators=[DataRequired()])
    submit = SubmitField('Submit')

# Create a Form Class
class PasswordForm(FlaskForm):
    email = StringField("What's Your Email:", validators=[DataRequired()])
    password_hash = PasswordField("What's Your password:", validators=[DataRequired()])
    submit = SubmitField('Submit')


# Add user
@helloapp.route('/user/add', methods=['GET',"POST"])
def add_user():
	name = None
	form = UserForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:
			# Hash the password!!!
			hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
			user = Users(username=form.username.data, name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()
		name = form.name.data
		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.favorite_color.data = ''
		form.password_hash.data = ''

		flash("User Added Successfully!")
	our_users = Users.query.order_by(Users.date_added)
	return render_template("add_user.html", 
		form=form,
		name=name,
		our_users=our_users)



@helloapp.route('/',methods=['GET']) 
def index():
    frist_name = 'John'
    stuff = 'This is <strong> Bold </strong> Text'
    return render_template('index.html', frist_name=frist_name, stuff=stuff)

# localhost:3700/user/danny
@helloapp.route('/user/<name>', methods=['GET'])
def user(name):
    return render_template('user.html', user_name=name)

# Invalid URL
@helloapp.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Internal Server Error
@helloapp.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


# Create password test page
@helloapp.route('/test_pw', methods=["GET", 'POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = False
    form = PasswordForm()
    # Validate Form
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        # Clear the Form
        form.email.data = ''
        form.password_hash.data = ''
        
        # Lookup user by email address
        pw_to_check = Users.query.filter_by(email=email).first()
        if pw_to_check is not None:
            # Check hashed password 
            passed = check_password_hash(pw_to_check.password_hash, password)
    
    return render_template('test_pw.html', email=email, password=password, form=form, pw_to_check=pw_to_check, passed=passed)




        # flash("Form submitted successfully")
    return render_template('test_pw.html', email=email,password=password,form=form,pw_to_check=pw_to_check,passsed=passsed)




# Create Name page
@helloapp.route('/name', methods=["GET", 'POST'])
def name():
    name = None
    form = NamerForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form submitted successfully")
    return render_template('name.html', name=name, form=form)

# Initialize the database
def initialize_database():
    with helloapp.app_context():
        db.create_all()



# To change port
if __name__ == "__main__":
    with helloapp.app_context():
        initialize_database()
        helloapp.run(port=4100, debug=True)