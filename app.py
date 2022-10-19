import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"],)
    stocks = db.execute("SELECT symbol, SUM(shares) as shares, operation FROM stocks WHERE userID = ? GROUP BY symbol HAVING (SUM(shares)) > 0;",session["user_id"],)
    total_cash_stocks = 0

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["shares"]
        total_cash_stocks = total_cash_stocks + stock["total"]

    total_cash = total_cash_stocks + user_cash[0]["cash"]
    return render_template("index.html", stocks=stocks, user_cash=user_cash[0], total_cash=total_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    #check if user input stock symbol for searching
    if request.method == "POST":
        symbol = request.form.get("symbol")
        price = lookup(symbol)
        shares = request.form.get("shares")
        user_cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])[0]["cash"]

        #check if symbol field valid:
        if not symbol:
            return apology("Please enter valid symbol",400)
        #check price
        elif price is None:
            return apology("Please enter valid symbol",400)

        try:
            shares = int(shares)
            if shares < 1:
                return apology("share must be a positive integer", 400)
        except ValueError:
            return apology("share must be a positive integer", 400)

        #get variable "share_price"
        share_price = shares * price["price"]
        #check if user have enough cash to do transaction
        if user_cash < share_price:
            return apology("You don't have enough money", 400)
        else:
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", share_price, session["user_id"],)
            db.execute("INSERT INTO stocks (userID, symbol, shares, price, operation) VALUES (?, ?, ?, ?, ?)",session["user_id"], symbol.upper(), shares, price["price"],"buy",)

        flash("Transaction successful")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    #all transactions
    stocks = db.execute("SELECT * FROM stocks WHERE userID = ?", session["user_id"])
    return render_template("history.html", stocks = stocks)


@app.route("/login", methods=["GET", "POST"])
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    #check if user input stock symbol for searching
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        #check if user input valid symbol
        if quote is None:
            return apology("Not valid symbol", 400)
        else:
            return render_template("quoted.html", name=quote["name"], symbol = quote["symbol"], price = quote["price"],)

    # User reached route by method "GET"
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    #"""Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        #check if user enter username when register
        if not username:
            return apology("Please enter username", 400)
        elif len(rows) != 0:
            return apology("username was taken", 400)

        #check if user enter password when register
        elif not password:
            return apology("Please enter password", 400)

        #check if confirmation password match with origin password
        elif not password == confirmation:
            return apology("passwords must match", 400)

        #if there is no error, insert username and password into DB
        else:
            # Generate the hash of the password
            hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

            # Insert the new user
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash )
            # Redirect user to home page
            return redirect("/")

        #if user reach route via Get, redirect to register page.
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        #define varaible
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        #check if symbol valid
        try:
            shares = int(shares)
            if shares < 1:
                return apology("invalid shares")
        except ValueError:
            return apology("invalid shares")
        if not symbol:
            return apology("symbol invalid")
        #get stocks
        stocks = db.execute("SELECT sum(shares) AS shares FROM stocks WHERE userID =? and symbol =?", session["user_id"], symbol)[0]

        if shares > stocks["shares"]:
            return apology("you dont have enough shares")
        price = lookup(symbol)["price"]
        shares_value = price * shares

        db.execute("INSERT INTO stocks(userID, symbol, shares, price, operation) VALUES (?,?,?,?,?)", session["user_id"], symbol.upper(),-shares, price, "sell", )
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", shares_value, session["user_id"],)

        flash("SOLD")
        return redirect("/")
    else:
         stocks = db.execute("SELECT symbol FROM stocks WHERE userID = ? GROUP BY symbol",session["user_id"],)
         return render_template("sell.html", stocks=stocks)

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        input_password = request.form.get("old_password")              #getting user input
        new_password = request.form.get("new_password")
        password_confirmation = request.form.get("new_password")


        new_password_hash = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=8)                 #getting hash of user new password
        user_current_password_hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"]) #get user password hash

        #check if user missin any fields:
        if not input_password or not new_password or not password_confirmation:
            return apology("Missing field", 400)

        #check new password confimation:
        if new_password != password_confirmation:
            return apology("new password confirmation failed")

        #chech if new password is the same with current password
        if input_password == new_password :
            return apology("your new password can not be the same with the previous", 400)

        #check if current password is what user entered
        if not check_password_hash(user_current_password_hash[0]["hash"],input_password):
            return apology("Your input password is not match with our DB", 400)
        else:
            db.execute("UPDATE users SET hash = ?", new_password_hash )
            flash("Password has been changed")
            return redirect("/")
    else:
        return render_template("change.html")
