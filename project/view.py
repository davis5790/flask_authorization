from flask import Flask
from flask_login import LoginManager
from models import User
from db import db
from flask_migrate import Migrate
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()
    
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user.
    return User.query.get(int(user_id))

from main import main as main_blueprint
app.register_blueprint(main_blueprint)

from auth import auth as auth_blueprint
app.register_blueprint(auth_blueprint)


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, port=port, host='0.0.0.0')