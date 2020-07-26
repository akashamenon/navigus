from flask import Flask, render_template, request, url_for, redirect, flash, \
session, abort
from flask_sqlalchemy import sqlalchemy, SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash



db_name = "auth.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# SECRET_KEY required for session, flash and Flask Sqlalchemy to work
app.config['SECRET_KEY'] = 'configure strong secret key here'

db = SQLAlchemy(app)


class User(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    pass_hash = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '' % self.username


def create_db():
    """ # Execute this first time to create new db in current directory. """
    db.create_all()
    print("DB Initialized")



@app.route("/signup/", methods=["GET", "POST"])
def signup():
    try:
        """
    Implements signup functionality. Allows username and password for new user.
    Hashes password with salt using werkzeug.security.
    Stores username and hashed password inside database.

    Username should to be unique else raises sqlalchemy.exc.IntegrityError.
    """

        if request.method == "POST":
            username = request.form['username']
            password = request.form['password']

        if not (username and password):
            flash("Username or Password cannot be empty")
            return redirect(url_for('signup'))
        else:
            username = username.strip()
            password = password.strip()

        # Returns salted pwd hash in format : method$salt$hashedvalue
        hashed_pwd = generate_password_hash(password, 'sha256')

        new_user = User(username=username, pass_hash=hashed_pwd)
        db.session.add(new_user)

        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash("Username {u} is not available.".format(u=username))
            return redirect(url_for('signup'))

        flash("User account has been created.")
        return redirect(url_for("login"))
    except:
        print("")

    return render_template("signup.html")


@app.route("/", methods=["GET", "POST"])
def home():

    if "username" in session:
        username = session['username']
    else:
        username = "admin"
        return render_template("home.html", username=username)

def login():
    """
    Provides login functionality by rendering login form on get request.
    On post checks password hash from db for given input username and password.
    If hash matches redirects authorized user to home page else redirect to
    login page with error message.
    """
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

    if not (username and password):
        flash("Username or Password cannot be empty.")
        return redirect(url_for('login'))
    else:
        username = username.strip()
        password = password.strip()

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.pass_hash, password):
        session[username] = True
        session["authorized"] = True
        session["username"] = username

        print(session["username"])

        return redirect(url_for("home", username=username))
    else:
        flash("Invalid username or password.")



    return render_template("login.html")


@app.route("/user/<username>/")
def user_home(username):
    """
    Home page for validated users.

    """
    if not session.get(username):
        return render_template("error.html")


    return render_template("user.html", username=username)


@app.route("/logout/<username>")
def logout(username):

    """ Logout user and redirect to login page with success message."""
    session.pop(username, None)
    session["authorized"] = False
    session["username"] = None



    flash("successfully logged out.")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
