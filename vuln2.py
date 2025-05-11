# vuln_extra.py

from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/xss")
def xss():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"  # Reflected XSS

@app.route("/sql")
def sql():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # SQL Injection
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return str(data)

@app.route("/csrf", methods=["POST"])
def csrf():
    password = request.form.get("password")
    # No CSRF token check!
    return f"Password changed to: {password}"

if __name__ == "__main__":
    app.run(debug=True)
