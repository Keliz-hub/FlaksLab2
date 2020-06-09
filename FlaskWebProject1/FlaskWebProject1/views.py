import hashlib
import os

from FlaskWebProject1 import app
from datetime import datetime
from flask import Flask, render_template, flash, redirect, url_for, json, Response, request
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, BooleanField, SubmitField
from flask_login import current_user, login_user, logout_user, UserMixin, LoginManager
from wtforms.validators import DataRequired

from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.http import MediaIoBaseDownload,MediaFileUpload
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import io
import pprint
import pickle
from werkzeug import secure_filename

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'D:\projectPython\FlaskWeb\FlaskWeb\FlaskWeb\credentials.json'

creds = None
   
if os.path.exists('token.pickle'):
    with open('token.pickle', 'rb') as token:
        creds = pickle.load(token)
   
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('D:\projectPython\FlaskWeb\FlaskWeb\FlaskWeb\credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
       
    with open('token.pickle', 'wb') as token:
        pickle.dump(creds, token)

service = build('drive', 'v3', credentials = creds)


app.config['SECRET_KEY'] = 'fuck_flask_and_other_python_shit'
posts = [{ 'user':'Бот', 'message':'Всем привет' }]
username = "Name"
personalArea = "Sign In"
loginManager = LoginManager(app)

class User(UserMixin):
    KEY_LOGIN = 'login'
    KEY_PASSW = 'passw'

    userList = None

    login = ''
    passw = ''
    is_external = False

    def __init__(self, data):
        self.login = data[User.KEY_LOGIN]
        self.passw = data[User.KEY_PASSW]
           
    
    def avatar_url(self):
        try:
            return self.info['photo_50']
        except AttributeError:
            return ''

    def get_id(self):
        return self.login


    def check_password(self, password):
        print(hashlib.md5(password.encode('utf-8')).hexdigest())
        return hashlib.md5(password.encode('utf-8')).hexdigest() == self.passw

    def __repr__(self):
        return F'User: {self.login}'

    def get_full_name(self):
        try:
            return self.info['first_name'] + ' ' + self.info['last_name']
        except AttributeError:
            return self.login


    @staticmethod
    @loginManager.user_loader
    def load_user(_login):
        if _login not in User.userList:
            return None
        else:
            return User.userList[_login]

    @staticmethod
    def load(_context):
        if not User.userList:
            filename = os.path.join(_context.root_path, 'data', 'userdata.json')
            file = open(filename, 'r')
            data = json.load(file)
            file.close()

            User.userList = {}
            for item in data:
                User.userList[item['login']] = User(item)

    @staticmethod
    def addUser(_context ,username, password):
         if username not in User.userList:
            filename = os.path.join(_context.root_path, 'data', 'userdata.json')
            file = open(filename, 'r')
            data = json.load(file)
            data += [{'login': username, 'passw': hashlib.md5(password.encode('utf-8')).hexdigest() }]
            print(data)
            file.close()

            with open(filename, 'w') as outfile:
                json.dump(data, outfile)

            for item in data:
                if User(item) not in User.userList:
                    User.userList[item['login']] = User(item)            

User.load(app)

@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
    file = request.files['file']
    name = secure_filename(file.filename) 
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], name))
    path = os.path.dirname(file)

    folder_id = '1MhbWIU7VEtY01YZsWkzGMWyojBn8xFk2eAUectEAo6c'
      
    file_metadata = {
                    'name': name,
                    'parents': [folder_id]
                }
    media = MediaFileUpload(path, resumable=True)
    r = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        
    return redirect(url_for('contact'))

  
@app.route('/loader', methods = ['GET', 'POST'])
def loader():
    if request.method == 'POST':
            file_id = request.form['id']
            file_name= request.form['name']
            requestApi = service.files().get_media(fileId=file_id)
            filename = file_name
            fh = io.FileIO(filename, 'wb')
            downloader = MediaIoBaseDownload(fh, requestApi)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
                print ("Download %d%%." % int(status.progress() * 100))
    return redirect(url_for('contact'))

@app.route('/contact')
def contact():
    """Renders the contact page."""    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    results = service.files().list(
        pageSize=200, fields="nextPageToken, files(id, name)").execute()
 
    items = results.get('files', [])
       
    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print(u'{0} ({1})'.format(item['name'], item['id']))          
            page_token = None

    return render_template('contact.html',
        title='Google Drive Api',
        items = items,
        year=datetime.now().year,
        personalText = current_user.login, 
        logoutText = "Logout",
        message='You can load and download files from your google cloud.')

@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    global personalArea
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    someUserName = current_user.login
    
    global posts
    
    
    return render_template('index.html',
        title=username,       
        personalText = someUserName,        
        year=datetime.now().year,
        logoutText = "Logout",
        posts = posts
    )


@app.route('/messagePost/', methods=['GET', 'POST'])
def messagePost():
    global posts    
    posts+=[{'user':current_user.login, 'message':request.form['inputText']}]
    return redirect(url_for('home'))




@app.route('/about')
def about():
    """Renders the about page."""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('about.html',
        title='About',
        year=datetime.now().year,
        message='Enjoy the silence',
        logoutText = "Logout",
        personalText = current_user.login)

@app.route('/login', methods=['GET', 'POST'])
def login():    
    print("")
    if current_user.is_authenticated:
        return redirect(url_for('userProfile'))
        # return redirect("/home")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.load_user(form.username.data)
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')            
            return redirect(url_for('login'))
        login_user(user)
      
        return redirect("/home")
    return render_template('login.html',  title='Sign In', form=form)

@app.route('/userProfile', methods=['GET', 'POST'])
def userProfile():    
    
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    return render_template('userProfile.html',
                           title="Hello, "+ current_user.login,
                           message = "Whats Up? Nice log bro...",
                           personalText = current_user.login,
                           logoutText = "Logout"
                           )

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/registration/', methods = ['POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():        
        user = User.load_user(form.username.data)
        if user is None and form.password.data == form.passwordLast.data :
            User.addUser(app, form.username.data, form.password.data)               
            return redirect(url_for('login'))      
              
        return redirect("/registration")
    return render_template('registration.html',  title='Registration', form=form)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    passwordLast = PasswordField('Password', validators=[DataRequired()])   
    submit = SubmitField('Registration')
