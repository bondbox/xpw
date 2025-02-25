# coding:utf-8

from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session

USERNAME = "admin"
PASSWORD = "secret"

app = Flask(__name__)
app.secret_key = "your_secret_key"


def check_auth(username, password):
    return username == USERNAME and password == PASSWORD


@app.route("/", methods=["POST"])
def login_post():
    username = request.form["username"]
    password = request.form["password"]
    if check_auth(username, password):
        session["user_token"] = True
        return redirect("/")
    else:
        return "Invalid username or password", 401


@app.route("/", methods=["GET"])
def login_get():
    return render_template("login.html",
                           username="账号",
                           password="密码",
                           submit="登录")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
