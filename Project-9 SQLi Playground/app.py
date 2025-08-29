from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecret"   # required for session handling

DB = "data.db"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        con = sqlite3.connect(DB)
        cur = con.cursor()
        # vulnerable query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cur.execute(query)
        row = cur.fetchone()
        con.close()

        if row:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            message = "Invalid credentials (Vulnerable Login)"
    return render_template("login.html", message=message)

@app.route("/safe_login", methods=["GET", "POST"])
def safe_login():
    message = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        con = sqlite3.connect(DB)
        cur = con.cursor()
        # safe query with parameterization
        query = "SELECT * FROM users WHERE username=? AND password=?"
        cur.execute(query, (username, password))
        row = cur.fetchone()
        con.close()

        if row:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            message = "Invalid credentials (Safe Login)"
    return render_template("safe_login.html", message=message)

@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return redirect(url_for("index"))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)

