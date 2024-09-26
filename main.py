import os
from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import update
from sqlalchemy.testing.pickleable import User

from forms import TaskListForm, TaskForm, RegisterForm, LoginForm
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, Boolean
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from typing import List

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class TaskLists(db.Model):
    __tablename__ = "taskLists"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_list_name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    tasks = relationship('Tasks', backref='task_list', cascade='all, delete-orphan')


class Tasks(db.Model):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_text: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    task_list_id: Mapped[int] = mapped_column(ForeignKey("taskLists.id"))
    task_done: Mapped[str] = mapped_column(Boolean, nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    tasks = relationship('Tasks', backref='user', cascade='all, delete-orphan')
    task_lists = relationship('TaskLists', backref='user', cascade='all, delete-orphan')


with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("index.html")

@app.route('/task_list_creation', methods=['GET', 'POST'])
def task_list_creation():
    task_list_form = TaskListForm()
    if task_list_form.validate_on_submit():
        new_task_list = TaskLists(task_list_name=task_list_form.task_list_name.data.capitalize(), user_id=current_user.id)
        db.session.add(new_task_list)
        db.session.commit()
        return redirect(url_for('newTaskList', task_list_name=task_list_form.task_list_name.data.capitalize()))
    return render_template("task_list_creation.html", form=task_list_form)


@app.route('/newTaskList/<task_list_name>', methods=['GET', 'POST'])
def newTaskList(task_list_name):
    task_form = TaskForm()
    task_list = TaskLists.query.filter_by(task_list_name=task_list_name).scalar()
    all_tasks = Tasks.query.filter_by(task_list_id=task_list.id).all()
    if task_form.validate_on_submit():
        new_task = Tasks(task_text=task_form.task_name.data, user_id=current_user.id, task_list_id=task_list.id, task_done=False)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('newTaskList', task_list_name=task_list_name))
    return render_template("newTaskList.html", form=task_form, task_list_name = task_list_name, all_tasks=all_tasks)

@app.route('/delete_task/<task_id>', methods=['GET', 'POST'])
def delete_task(task_id):
    task_to_delete = db.get_or_404(Tasks, task_id)
    task_list_id = task_to_delete.task_list_id
    task_list_name = db.get_or_404(TaskLists, task_list_id).task_list_name
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('newTaskList', task_list_name=task_list_name))

@app.route('/done_task/<task_id>', methods=['GET', 'POST'])
def done_task(task_id):
    db.session.execute(update(Tasks).where(Tasks.id == task_id).values(task_done=True))
    db.session.commit()
    task_cross_out = db.get_or_404(Tasks, task_id)
    task_to_update = db.get_or_404(Tasks, task_id)
    task_list_id = task_to_update .task_list_id
    task_list_name = db.get_or_404(TaskLists, task_list_id).task_list_name
    return redirect(url_for('newTaskList', task_list_name=task_list_name))


@app.route('/task_list', methods=['GET', 'POST'])
def task_list():
    task_list = TaskLists.query.filter_by(user_id=current_user.id).all()
    return render_template("list_of_tasks.html", task_list=task_list)

@app.route('/delete_list/<list_id>', methods=['GET', 'POST'])
def delete_list(list_id):
    task_list_to_delete= db.get_or_404(TaskLists, list_id)
    db.session.delete(task_list_to_delete)
    db.session.commit()
    return redirect(url_for('task_list'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data.lower()
        hashed_password = generate_password_hash(password=register_form.password.data, method='pbkdf2:sha256', salt_length=8)
        if db.session.query(User).filter_by(email=email).scalar():
            flash("User already exists new")
            return redirect(url_for('login'))
        else:
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data.lower()
        user = User.query.filter_by(email=email).scalar()
        if user:
            if check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Invalid Username or password, please check your email and password", 'error')
        else:
            flash("User not found, please check your email and password", 'error')
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)