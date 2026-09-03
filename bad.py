import sqlite3
def f(u):
    c=sqlite3.connect("a").cursor()
    c.execute("SELECT * FROM t WHERE id = " + u)
