from datetime import date
import os
from flask import Flask, abort, render_template, redirect, url_for, request, jsonify
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)


# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI','sqlite:///posts.db')
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)


class Comments(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    name = db.Column(db.String(250), db.ForeignKey('users.name'))
    body = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(id):
    return db.get_or_404(User, id)


with app.app_context():
    db.create_all()


# Admin only decorator
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        post = db.get_or_404(BlogPost, kwargs['post_id'])
        if current_user.id == post.author_id:
            return f(*args, **kwargs)
        if current_user.email != "admin@email.com":
            return abort(400, 'You don\'t have permission to do this!')
        return f(*args, **kwargs)
    return wrapper


# Logout needed decorator
def need_logout(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return abort(400, "Need logout to do this!")
        return f(*args, **kwargs)
    return wrapper

# Create error code
@app.errorhandler
def custom400(error):
    response = jsonify({
        'message': error.description['message']
    })


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
@need_logout
def register():
    form = CreateRegisterForm()
    error = None
    if request.method == "POST" and form.validate():
        user: User = User(
            name=form.name.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data, method='pbkdf2', salt_length=16)
        )
        try:
            db.session.add(user)
            db.session.commit()
        except:
            error = "Email has already registered!"
            return render_template("register.html", form=form, error=error)
        else:
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, error=error)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["POST", "GET"])
@need_logout
def login():
    form = CreateLoginForm()
    error = None
    if request.method == 'POST' and form.validate():
        user = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = user.scalar()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                error = 'Password not correct. Please type again!'
                return render_template("login.html", form=form, error=error)
        else:
            error = 'Invalid Email.'
            return render_template("login.html", form=form, error=error)
    return render_template("login.html", form=form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    is_admin = False
    logged_in = current_user.is_authenticated
    name = None
    if logged_in:
        name = current_user.name
        if current_user.email == "admin@email.com":
            is_admin = True
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=logged_in,
                           name=name, is_admin=is_admin)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CreateCommentForm()
    logged_in = current_user.is_authenticated
    is_user = False
    is_admin = False
    error = None
    name = None
    requested_post = db.get_or_404(BlogPost, post_id)
    if logged_in:
        is_user = True
        name = current_user.name
        if current_user.id != requested_post.author_id:
            is_user = False
        if current_user.email == "admin@email.com":
            is_admin = True
    if request.method == "POST" and form.validate() and logged_in:
        new_comment: Comments = Comments(
            post_id=post_id,
            user_id=current_user.id,
            name=current_user.name,
            body=form.body.data
        )
        db.session.add(new_comment)
        db.session.commit()
    elif request.method == "POST" and form.validate and not logged_in:
        error = "You need login to comment."
    comments = [comment for comment in db.session.execute(db.select(Comments).where(Comments.post_id == post_id)).scalars().all()]
    return render_template("post.html", post=requested_post, logged_in=logged_in, name=name
                           ,is_admin=is_admin, is_user=is_user, form=form, comments=comments, error=error)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    logged_in = current_user.is_authenticated
    name = None
    if logged_in:
        name = current_user.name
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            author_id=current_user.id,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, name=name, logged_in=logged_in)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True,
                           logged_in=True, name=current_user.name, post_id=post_id)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    logged_in = current_user.is_authenticated
    name = None
    if logged_in:
        name = current_user.name
    return render_template("about.html", logged_in=logged_in, name=name)


@app.route("/contact")
def contact():
    logged_in = current_user.is_authenticated
    name = None
    if logged_in:
        name = current_user.name
    return render_template("contact.html", logged_in=logged_in, name=name)


if __name__ == "__main__":
    app.run(debug=False, port=5002)
