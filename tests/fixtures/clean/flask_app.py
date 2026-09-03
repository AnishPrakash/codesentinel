import hashlib
import os

from flask import Flask, request
from flask_login import current_user, login_required

from db import session

app = Flask(__name__)

AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/user/<uid>")
@login_required
def get_user(uid):
    row = session.execute(
        "SELECT * FROM users WHERE id = :uid AND owner_id = :owner",
        {"uid": uid, "owner": current_user.id},
    ).first()
    return {"row": dict(row) if row else None}


@app.route("/hash")
@login_required
def make_hash():
    value = request.args.get("value", "")
    return hashlib.sha256(value.encode()).hexdigest()
