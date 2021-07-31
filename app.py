import os
import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///dbbase.db")


#################################################################################################


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/employees", methods=["GET", "POST"])
@login_required
def employees():
    if request.method == "POST":
        name = request.form.get("name")
        job = request.form.get("job")
        phone = request.form.get("phone")
        if not name:
            flash("Input Name")
            return redirect("/employees")
        name = name.strip()
        if job:
            job = job.strip()
        if phone:
            phone = phone.strip()

        name_exist = db.execute("SELECT * FROM employees WHERE name=?", name)
        if name_exist:
            flash("Name Already Exists")
            return redirect("/employees")
        db.execute(
            "INSERT INTO employees (name , Job, phone) VALUES(?, ?, ?)", name, job, phone)
        flash("Added")
        return redirect("/employees")
    employees = db.execute("SELECT * FROM employees")
    return render_template("employees.html", page="employees", employees=employees)


@app.route("/operations", methods=["GET", "POST"])
@login_required
def operation():
    if request.method == "POST":
        operation_name = request.form.get("operation_name")
        location = request.form.get("location")
        sub_contractor = request.form.get("sub_contractor")
        if not operation_name:
            flash("Input Operation Name")
            return redirect("/operations")
        operation_name = operation_name.strip()
        if location:
            location = location.strip()

        if sub_contractor:
            sub_contractor = sub_contractor.strip()

        operation_exist = db.execute(
            "SELECT * FROM operations WHERE op_name = ?", operation_name)
        if operation_exist:
            flash("Operation Name already exists")
            return redirect("/operations")
        db.execute("INSERT INTO operations (op_name,location,sub_contractor) VALUES (?, ?, ?)",
                   operation_name, location, sub_contractor)
        flash("Added")
        return redirect("/operations")

    operations = db.execute("SELECT * FROM operations")
    people = db.execute("SELECT name FROM employees")

    return render_template("operations.html", page="operation", operations=operations, people=people)


@app.route("/database", methods=["GET", "POST"])
@login_required
def database():
    if request.method == "POST":
        employee = request.form.get("employee")

        if not employee:
            flash("Select Employee")
            return redirect("/database")

        fdescription = request.form.get("fdescription")
        if not fdescription:
            flash("Input Type 'Description'")
            return redirect("/database")

        fcash = request.form.get("fcash")
        if not fcash:
            flash("Input Cash amount")
            return redirect("/database")

        foperation = request.form.get("operation")
        if not foperation:
            flash("Select Operation")
            return redirect("/database")

        fdate = request.form.get("fdate")
        if not fdate:
            flash("Select a date")
            return redirect("/database")

        employee = employee.strip()
        fdescription = fdescription.strip()
        fcash = fcash.strip()
        foperation = foperation.strip()
        fdate = fdate.strip()
        employee_id = db.execute(
            "SELECT id FROM employees WHERE name = ?", employee)[0]["id"]
        operation_id = db.execute(
            "SELECT id FROM operations WHERE op_name = ?", foperation)[0]["id"]
        db.execute("INSERT INTO dbbase (employeeId, employee_name, description, cash, operation_id, operation_name,timestamp) VALUES (?, ?,?, ?, ?, ?, ?)",
                   employee_id, employee, fdescription, fcash, operation_id, foperation, fdate)
        flash("Added")
        return redirect("/database")
    people = db.execute("SELECT name FROM employees")
    operations = db.execute("SELECT op_name FROM operations")
    dbbase = db.execute("SELECT * FROM dbbase ORDER BY timestamp DESC")
    return render_template("database.html", page="database", people=people, operations=operations, dbbase=dbbase)


@app.route("/edit_employees", methods=["GET", "POST"])
@login_required
def edit_employees():
    if request.method == "POST":
        deleteid = request.form.get("Edeleteid")
        if deleteid:
            dbsearch = db.execute(
                "SELECT * FROM dbbase WHERE employeeId = ?", deleteid)
            if dbsearch:
                flash("Employee Has entries in Database")
                return redirect("/edit_employees")
            db.execute("DELETE FROM employees where id = ?", deleteid)
            return redirect("/employees")
        Ename = request.form.get("editname")
        Ephone = request.form.get("editphone")
        Ejob = request.form.get("editjob")
        Editid = int(request.form.get("editid"))
        if Ename:
            dbsearch = db.execute(
                "SELECT * FROM dbbase WHERE employeeId = ?", Editid)
            if dbsearch:
                flash("Employee Has entries in Database")
                return redirect("/edit_employees")
            Ename = Ename.strip()
            nameexist = db.execute(
                "SELECT * FROM employees WHERE name = ?", Ename)
            if nameexist:
                flash("Name Already Exists")
                return redirect("/employees")
            db.execute("UPDATE employees SET name =? WHERE id=?", Ename, Editid)
        if Ephone:
            Ephone = Ephone.strip()
            db.execute("UPDATE employees SET phone =? WHERE id=?",
                       Ephone, Editid)
        if Ejob:
            Ejob = Ejob.strip()
            db.execute("UPDATE employees SET Job =? WHERE id=?", Ejob, Editid)
    return redirect("/employees")


@app.route("/edit_operations", methods=["GET", "POST"])
@login_required
def edit_operations():
    if request.method == "POST":
        deleteid = request.form.get("Odeleteid")
        if deleteid:
            dbsearch = db.execute(
                "SELECT * FROM dbbase WHERE operation_id = ?", deleteid)
            if dbsearch:
                flash("Operation Has entries in Database")
                return redirect("/edit_operations")
            db.execute("DELETE FROM operations where id = ?", deleteid)
            return redirect("/operations")
        Eop = request.form.get("editop")
        Elocation = request.form.get("editlocation")
        Esub = request.form.get("editsub")
        Editid = int(request.form.get("editid"))

        if Eop:
            dbsearch = db.execute(
                "SELECT * FROM dbbase WHERE operation_id = ?", Editid)
            if dbsearch:
                flash("Operation Has entries in Database")
                return redirect("/edit_operations")
            Eop = Eop.strip()
            opexist = db.execute(
                "SELECT * FROM operations WHERE name = ?", Eop)
            if opexist:
                flash("Operation Already Exists")
                return redirect("/operations")
            db.execute(
                "UPDATE operations SET op_name =? WHERE id=?", Eop, Editid)
        if Elocation:
            Elocation = Elocation.strip()
            db.execute("UPDATE operations SET location =? WHERE id=?",
                       Elocation, Editid)
        if Esub:
            Esub = Esub.strip()
            db.execute(
                "UPDATE operations SET sub_contractor =? WHERE id=?", Esub, Editid)
    return redirect("/operations")


@app.route("/edit_database", methods=["GET", "POST"])
@login_required
def edit_database():
    if request.method == "POST":
        editid = request.form.get("editid")
        deleteid = request.form.get("Ddeleteid")
        if deleteid:
            db.execute("DELETE FROM dbbase where id = ?", deleteid)
            return redirect("/database")

        editname = request.form.get("editEmpName")
        if editname:
            editname = editname.strip()
            checkname = db.execute(
                "SELECT * FROM employees WHERE name = ?", editname)
            if not checkname:
                flash("Employee Doesnt Exist")
                return redirect("/database")

            empId = db.execute("SELECT id FROM employees WHERE name=?", editname)[
                0]["id"]
            db.execute(
                "UPDATE dbbase SET employeeId = ? WHERE id = ?", empId, editid)
            db.execute(
                "UPDATE dbbase SET employee_name = ? WHERE id = ?", editname, editid)

        editdes = request.form.get("editDes")
        if editdes:
            editdes = editdes.strip()
            db.execute(
                "UPDATE dbbase SET description = ? WHERE id = ?", editdes, editid)
        editcash = request.form.get("editCash")
        if editcash:
            db.execute("UPDATE dbbase SET cash = ? WHERE id = ?",
                       editcash, editid)
        editop = request.form.get("editOpName")
        if editop:
            editop = editop.strip()
            checkop = db.execute(
                "SELECT * FROM operations WHERE op_name = ?", editop)
            if not checkop:
                flash("Operation Doesnt Exist")
                return redirect("/database")

            opId = db.execute("SELECT id FROM operations WHERE op_name=?", editop)[
                0]["id"]
            db.execute(
                "UPDATE dbbase SET operation_id = ? WHERE id = ?", opId, editid)
            db.execute(
                "UPDATE dbbase SET operation_name = ? WHERE id = ?", editop, editid)

        edittime = request.form.get("editTime")
        if edittime:
            db.execute(
                "UPDATE dbbase SET timestamp = ? WHERE id = ?", edittime, editid)
        return redirect("/database")


####################################################################################################
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()
    username = request.form.get("username")
    password = request.form.get("password")
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not username:
            flash("UserName not available")
            return redirect("/login")
        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Provide Password")
            return redirect("/login")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    if request.method == "POST":
        checkdb = db.execute(
            "SELECT * FROM users WHERE username = ?", username)

        if len(checkdb) == 1:
            flash("UserName not available")
            return redirect("/register")

        if not username:  # Check if user inputted username
            flash("Missing UserName")
            return redirect("/register")

        if not password:  # Check if user inputted password
            flash("Missing Password")
            return redirect("/register")
        # Check if password == confirmation
        if password != request.form.get("confirmation"):
            flash("Passwords dont match")
            return redirect("/register")

        # The hash of the password user inputted
        hashed = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username , hash) VALUES (?, ?)", username, hashed)
        flash("User Added")
        return redirect("/")

    else:
        return render_template("register.html", page="register")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "POST":
        UserId = session["user_id"]  # user ID
        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        if not oldpassword:
            flash("Input Old Password")
            return redirect("/changepassword")

        if not newpassword:
            flash("Input New Password")
            return redirect("/changepassword")

        if not confirmation:
            flash("Wrong Confirmation")
            return redirect("/changepassword")

        hashed_password = db.execute(
            "SELECT hash FROM users WHERE id=?", UserId)
        check = check_password_hash(hashed_password[0]["hash"], oldpassword)
        if check == False:
            flash("Wrong password")
            return redirect("/changepassword")

        if oldpassword == newpassword:
            flash("Passwords are the same")
            return redirect("/changepassword")

        if newpassword != confirmation:
            flash("Passwords dont match")
            return redirect("/changepassword")

        db.execute("UPDATE users SET hash =? WHERE id=?",
                   generate_password_hash(newpassword), UserId)
        flash("Password Updated")
        return redirect("/")
    return render_template("changepass.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
