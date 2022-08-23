from crypt import methods
from importlib.metadata import requires
import os
from flask import Flask, send_file, render_template, url_for, request, redirect, session, g
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

#definisco il percorso relativo delle cartelle da qui prendere i file
TEMPLATE_DIR = os.path.abspath('../templates')
STATIC_DIR = os.path.abspath('../static')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)       
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
#inizializzo il gestore degli accessi 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#questa classe serve a definire la table per database.db
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

#questa funzione permette un collegamento tra flask e il database 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#in questa classe vengono definiti i dati necessari per l'accesso
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
 
#in questa classe vengono definiti i dati necessari per la registrazione
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    
    #funzione di controllo per verificare se una determinato username è già stato inserito nel database 
    def validate_username(self, username):
        existing_User_username = User.query.filter_by(
            username=username.data).first()
    
        if existing_User_username:
            raise ValidationError(
                "Username già esistente")
            
    #funzione di controllo per verificare se una determinata email è già stata inserita nel database 
    def validate_email(self, email):
        existing_User_email = User.query.filter_by(
            email=email.data).first()
        
        if existing_User_email:
            raise ValidationError(
                "Email già esistente")


#la funzione serve a fare accedere gli utenti al web server
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))

        return render_template('error.html', form=form)

    return render_template('login.html', form=form)


#la funzione serve a registrare gli utenti al web server
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html', form=form)
        
    return render_template('signup.html', form=form)

# permette all'utente di uscire dal sito
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# gestisce le richieste indirizzate alla pagina index.html 
@app.route('/')
@login_required
def index():
    return render_template('index.html',name=current_user.username)

# gestisce le richieste indirizzate alla pagina service.html
@app.route('/service')
@login_required
def service():
    return render_template('service.html',name=current_user.username)

# gestisce le richieste indirizzate alla pagina travel.html
@app.route('/travel')
@login_required
def travel():
    return render_template('travel.html',name=current_user.username)

#funzione per effettuare il download presente nell'homepage
@app.route('/download')
@login_required
def download_file():
    path = "static/src/locandina.pdf"
    return send_file(path, as_attachment=True)

#funzione per indirizzare i dati css al web server
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

#funzione creata per aggionare le cache del browser per problemi relativi all'aggionamento del codice css dell'webserver
def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                 endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

#premette l'avvio del server all'indirizzo 127.0.0.1:5800
if __name__ == "__main__":
    app.run(debug=True, threaded=True, host='127.0.0.1', port=5800)