from flask import Flask,session
from db import init_db
from routes.auth import auth_bp
from routes.trigger import trigger_bp
from apscheduler.schedulers.background import BackgroundScheduler
from routes.trigger import scheduler
app = Flask(__name__)
scheduler.start()
app.secret_key = ""  

init_db()

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(trigger_bp, url_prefix="/trigger")

if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0")
