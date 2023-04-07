from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, User, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    post = relationship('BlogPost', back_populates='author')
    comment = relationship('Comments', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("Users", back_populates="post")
    comment = relationship('Comments', back_populates='post')

class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    body = db.Column(db.Text, nullable=False)
    comment_author = relationship("Users", back_populates="comment")
    post = relationship('BlogPost', back_populates='comment')



with app.app_context():
    db.create_all()

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view



@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    posts = list(reversed(posts))
    return render_template("index.html", all_posts=posts, auth=current_user.is_authenticated, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = User()
    if form.validate_on_submit():
        user = Users(name=form.name.data,
                     email=form.email.data,
                     password=generate_password_hash(password=form.password.data, method='pbkdf2:sha256:150000',salt_length=16))
        if Users.query.filter_by(email=form.email.data).first():
            flash('Данный email уже используется')
            return redirect(url_for('login'))
        else:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect('/')
    return render_template("register.html", form=form, auth=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = User()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Не верный email или пароль')
            return redirect(url_for('login'))
    return render_template("login.html", form=form, auth=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments =  [i for i in Comments.query.all() if i.post_id == post_id]
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated != True:
            flash('Нужно выполнить вход в систему')
            return redirect(url_for('show_post', post_id=post_id))
        comment = form.body.data
        add_comment = Comments(body=form.body.data,
                               comment_author=current_user,
                               post=requested_post)
        db.session.add(add_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, auth=current_user.is_authenticated, current_user=current_user, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", auth=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", auth=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, auth=current_user.is_authenticated, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, auth=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    for i in Comments.query.filter_by(post_id=post_id).all():
        db.session.delete(i)
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
