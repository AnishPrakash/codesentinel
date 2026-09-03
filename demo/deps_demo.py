"""The dependency-firewall demo.

`pdfkit_lite` does not exist. It is the shape an assistant invents: plausible,
one edit away from a real package, and an attacker who registers it gets code
execution on every machine that runs the install command.
"""
import pdfkit_lite
import requests
from sqlalchemy import create_engine


def render(html: str) -> bytes:
    return pdfkit_lite.from_string(html)
