"""A local module the clean fixture imports.

It exists so the dependency firewall can see that `from db import session` is
the project's own code and not an unrecognised package.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
session = scoped_session(sessionmaker(bind=engine))
