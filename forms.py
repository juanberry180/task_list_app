from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, SelectField, PasswordField
from wtforms.validators import DataRequired, URL, Email, ValidationError, InputRequired


class TaskListForm(FlaskForm):
    task_list_name = StringField("Please enter the name of the new task list:", validators=[DataRequired()])
    submit = SubmitField("Submit")

class TaskForm(FlaskForm):
    task_name = StringField("Please enter new task:", validators=[DataRequired()])
    submit = SubmitField("Submit")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log me in!")