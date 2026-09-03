"""A route that trips advisories only.

It changes state and lives at an auth-shaped path, but there is no injection,
no credential, no weak hash and no unauthenticated data read - so the only
things CodeSentinel has to say about it are advisory.
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/auth/session", methods=["POST"])
def create_session():
    return jsonify({"ok": True})
