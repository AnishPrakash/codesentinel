"""Allows `python -m codesentinel`, which is how the VS Code extension invokes
the tool: it does not depend on the console script being on PATH."""
from .cli import app

if __name__ == "__main__":
    app()
