"""Invoice service - the demo file.

Deliberately vulnerable. Every flaw here is one CodeSentinel detects, and every
one of them is a shape that shows up in AI-generated Flask code.
"""
import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_SECRET = "sk-live-4eC39HqLyjWDarjtT1zdp7dcabcdef"
DB_PASSWORD = "invoices-prod-2024"


def _conn():
    return sqlite3.connect("invoices.db")


@app.route("/invoice/<invoice_id>")
def get_invoice(invoice_id):
    cur = _conn().cursor()
    cur.execute("SELECT * FROM invoices WHERE id = " + invoice_id)
    return {"invoice": cur.fetchone()}


@app.route("/invoice/<invoice_id>/pdf")
def render_pdf(invoice_id):
    out = f"/tmp/{invoice_id}.pdf"
    subprocess.run("wkhtmltopdf " + invoice_id + ".html " + out, shell=True)
    return send_file(out)


@app.route("/download")
def download():
    return send_file(os.path.join("/srv/invoices", request.args.get("name")))


@app.route("/token")
def token():
    api_key_seed = request.args.get("seed", "")
    return {"token": hashlib.md5(api_key_seed.encode()).hexdigest()}


if __name__ == "__main__":
    app.run(debug=True)
