import os
from flask import Flask, session
from flask_user import UserManager

import uscope.gsearch
import uscope.configure
from uscope.models import User



def create_app(test_config=None):
    app = Flask(__name__)
    
    if test_config is None:
        app.config.from_pyfile('./config.py', silent=False)
    else:
        app.config.from_pyfile('/tests/config.py', silent=True)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from uscope.db import db_session
    user_manager = UserManager(app, db_session, User)
    @app.route('/')
    def hello_world():
        return "<p>uScope is running</p>"

    app.register_blueprint(uscope.gsearch.bp)
    app.register_blueprint(uscope.configure.bp)
    
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()
    return app

if __name__ == "__main__":
    app = create_app()
    app.debug = True
    app.run()

