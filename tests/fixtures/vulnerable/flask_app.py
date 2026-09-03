import hashlib
import sqlite3

from flask import Flask, request

app = Flask(__name__)

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "hunter2-production-db"


@app.route("/user/<uid>")
def get_user(uid):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return {"rows": cur.fetchall()}


@app.route("/hash")
def make_hash():
    return hashlib.md5(request.args.get("value", "").encode()).hexdigest()
