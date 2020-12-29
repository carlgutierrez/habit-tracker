import os

import sqlite3
import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure sqlite3 to use database
conn = sqlite3.connect('main.db', check_same_thread=False)
c = conn.cursor()


@app.route("/")
@login_required
def index():
    date_today = datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d")
    c.execute("SELECT habit, previous_check_in, date_created, maximum_day_off FROM habits WHERE user_id = :user_id AND is_deleted = 0 AND is_deleted = 0 AND actual_days != target_days", {
              'user_id': session["user_id"]})
    check_if_updated_query = c.fetchall()

    for habit, previous_check_in, date_created, maximum_day_off in check_if_updated_query:
        if previous_check_in == ' ':
            previous_check_in = (datetime.datetime.strptime(
                date_created, '%Y-%m-%d %H:%M:%S')).strftime("%Y-%m-%d")

        # add 1 day for expected check in date
        maximum_day_off += 1

        expected_check_in = (datetime.datetime.strptime(previous_check_in, '%Y-%m-%d') +
                             datetime.timedelta(days=int(maximum_day_off))).strftime("%Y-%m-%d")

        if expected_check_in < date_today:
            with conn:
                c.execute("UPDATE habits SET actual_days = 0 WHERE user_id = :user_id and habit = :habit", {
                    'user_id': session["user_id"], 'habit': habit})

    c.execute(
        "SELECT habit, actual_days, target_days, previous_check_in, maximum_day_off, id, date_created FROM habits WHERE user_id = :user_id AND is_deleted = 0 AND actual_days != target_days ORDER BY priority DESC, habit", {'user_id': session["user_id"]})
    habits = c.fetchall()

    c.execute(
        "SELECT total_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
    total_habit_query = str(c.fetchall())
    if total_habit_query[3:4] == ',':
        total_habit = total_habit_query[2:3]
    else:
        total_habit = total_habit_query[2:4]

    c.execute(
        "SELECT finished_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
    finished_habit_query = str(c.fetchall())
    if finished_habit_query[5:6] == ',':
        finished_habit = finished_habit_query[2:5]
    elif finished_habit_query[4:5] == ',':
        finished_habit = finished_habit_query[2:4]
    else:
        finished_habit = finished_habit_query[2:3]

    return render_template("index.html", habits=habits, total_habit=total_habit, finished_habit=finished_habit)


@ app.route("/delete", methods=["GET", "POST"])
@ login_required
def delete():
    if request.method == "POST":
        date_created = request.form.get("delete_button")
        updated_total_habit = int(
            request.form.get("hidden_total_habit")) - int(1)
        with conn:
            c.execute("UPDATE habits SET is_deleted = 1 WHERE user_id = :user_id AND date_created = :date_created", {
                'user_id': session["user_id"], 'date_created': date_created})
            c.execute("UPDATE users SET total_habit = :updated_total_habit where id = :user_id", {
                'updated_total_habit': updated_total_habit, 'user_id': session["user_id"]})
        flash(f"Habit Deleted!")
        return redirect("/")


@ app.route("/update", methods=["GET", "POST"])
@ login_required
def update():
    if request.method == "POST":
        date_created = request.form.get("hidden_date_created")
        updated_actual_days = int(
            request.form.get("hidden_actual_days")) + int(1)
        targer_days = int(request.form.get("hidden_target_days"))
        previous_check_in = request.form.get("update_button")
        date_today = datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%d")

        if previous_check_in < date_today:
            with conn:
                c.execute("UPDATE habits SET previous_check_in = :date_today, actual_days = actual_days + 1 WHERE user_id = :user_id AND date_created = :date_created", {
                          'date_today': date_today, 'user_id': session["user_id"], 'date_created': date_created})

            # Check if the updated actual_days is equal to target_days then increment users finished_habit and decrement total_habit
            if updated_actual_days == targer_days:
                with conn:
                    c.execute("UPDATE users SET finished_habit = finished_habit + 1, total_habit = total_habit - 1 WHERE id = :user_id",
                              {'user_id': session["user_id"]})

            flash(f"Progress Updated!")
            return redirect("/")
        else:
            flash(f"Already updated for today!")
            return redirect("/")


@ app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        c.execute("SELECT * FROM users WHERE username = :username",
                  {'username': request.form.get("username")})
        rows = c.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@ app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@ app.route("/progress")
@ login_required
def progress():
    c.execute(
        "SELECT habit, actual_days, target_days FROM habits WHERE user_id = :user_id AND is_deleted = 0 AND actual_days != target_days ORDER BY priority DESC, habit", {'user_id': session["user_id"]})
    habits = c.fetchall()

    c.execute(
        "SELECT target_days FROM habits WHERE user_id = :user_id AND is_deleted = 0 AND actual_days != target_days ORDER BY target_days DESC", {'user_id': session["user_id"]})
    max_target_days_query = str(c.fetchall())
    if max_target_days_query[5:6] == ',':
        max_target_days = int(max_target_days_query[2:5]) + 10
    elif max_target_days_query[4:5] == ',':
        max_target_days = int(max_target_days_query[2:4]) + 10
    elif max_target_days_query[3:4] == ',':
        max_target_days = int(max_target_days_query[2:3]) + 10
    else:
        max_target_days = 0

    c.execute(
        "SELECT finished_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
    finished_habit_query = str(c.fetchall())
    if finished_habit_query[5:6] == ',':
        finished_habit = finished_habit_query[2:5]
    elif finished_habit_query[4:5] == ',':
        finished_habit = finished_habit_query[2:4]
    else:
        finished_habit = finished_habit_query[2:3]

    return render_template("progress.html", habits=habits, finished_habit=finished_habit, max_target_days=max_target_days)


@ app.route("/leaderboard")
@ login_required
def leaderboard():
    c.execute(
        "SELECT finished_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
    finished_habit_query = str(c.fetchall())
    if finished_habit_query[5:6] == ',':
        finished_habit = finished_habit_query[2:5]
    elif finished_habit_query[4:5] == ',':
        finished_habit = finished_habit_query[2:4]
    else:
        finished_habit = finished_habit_query[2:3]

    rankings = c.execute(
        "SELECT username, finished_habit FROM users ORDER BY finished_habit DESC, username")

    return render_template("leaderboard.html", rankings=rankings, finished_habit=finished_habit)


@ app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_confirmation = request.form.get("password_confirmation")

        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not password_confirmation:
            return apology("must confirm password", 403)
        elif password != password_confirmation:
            return apology("password don't match", 400)

        c.execute("SELECT * FROM users WHERE username = :user",
                  {'user': username})
        rows = c.fetchall()

        if len(rows) != 0:
            return apology("Username is not available", 400)
        else:
            with conn:
                c.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", {
                    'username': username, 'hash': generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)})

            c.execute("SELECT * FROM users WHERE username = :username",
                      {'username': username})
            rows = c.fetchall()

            session["user_id"] = rows[0][0]
            flash(f"Registered!")
            return redirect("/")
    else:
        return render_template("register.html")


@ app.route("/add", methods=["GET", "POST"])
@ login_required
def add():
    if request.method == "POST":
        habit = request.form.get("habit")
        priority = request.form.get("priority")
        target_days = request.form.get("targer_days")
        maximum_day_off = request.form.get("maximum_day_off")
        updated_total_habit = int(
            request.form.get("hidden_total_habit")) + int(1)

        with conn:
            c.execute("INSERT INTO habits (user_id, habit, priority, target_days, maximum_day_off, previous_check_in) VALUES (:user_id, :habit, :priority, :target_days, :maximum_day_off, ' ')", {
                'user_id': session["user_id"], 'habit': habit, 'priority': priority, 'target_days': target_days, 'maximum_day_off': maximum_day_off})
            c.execute("UPDATE users SET total_habit = :updated_total_habit WHERE id = :user_id", {
                      'updated_total_habit': updated_total_habit, 'user_id': session["user_id"]})
        flash(f"Habit Created!")
        return redirect("/")
    else:
        c.execute(
            "SELECT total_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
        total_habit = str(c.fetchall())

        c.execute(
            "SELECT finished_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
        finished_habit_query = str(c.fetchall())
        if finished_habit_query[5:6] == ',':
            finished_habit = finished_habit_query[2:5]
        elif finished_habit_query[4:5] == ',':
            finished_habit = finished_habit_query[2:4]
        else:
            finished_habit = finished_habit_query[2:3]

        return render_template("add.html", total_habit=total_habit, finished_habit=finished_habit)


@ app.route("/change_password", methods=["GET", "POST"])
@ login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password")
        old_password = request.form.get("old_password")
        old_password_confirmation = request.form.get(
            "old_password_confirmation")

        if not new_password:
            return apology("must provide new password", 400)
        elif not old_password:
            return apology("must provide old password", 400)
        elif not old_password_confirmation:
            return apology("must provide old password again", 400)
        elif old_password != old_password_confirmation:
            return apology("old passwords doesn't match", 400)

        c.execute("SELECT * FROM users WHERE id = :id",
                  {'id': session["user_id"]})
        req = c.fetchall()

        if len(req) != 1 or not check_password_hash(req[0][2], request.form.get("old_password")):
            return apology("invalid old password", 403)
        else:
            with conn:
                c.execute("UPDATE users SET hash = :hash WHERE id = :id", {'hash': generate_password_hash(
                    new_password, method="pbkdf2:sha256", salt_length=8), 'id': session["user_id"]})

            flash(f"Password Changed!")
            return redirect("/")

    else:
        c.execute(
            "SELECT finished_habit FROM users WHERE id = :user_id", {'user_id': session["user_id"]})
        finished_habit_query = str(c.fetchall())
        if finished_habit_query[5:6] == ',':
            finished_habit = finished_habit_query[2:5]
        elif finished_habit_query[4:5] == ',':
            finished_habit = finished_habit_query[2:4]
        else:
            finished_habit = finished_habit_query[2:3]

        return render_template("change_password.html", finished_habit=finished_habit)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
