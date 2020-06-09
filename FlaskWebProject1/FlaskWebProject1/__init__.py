"""
The flask application package.
"""

from flask import Flask
UPLOAD_FOLDER = 'C:\\Users\\Keliz\\source\\repos\\FlaskWebProject1\\FlaskWebProject1\\uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

import FlaskWebProject1.views
