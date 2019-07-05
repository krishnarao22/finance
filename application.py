import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    symbols = db.execute("SELECT symbol FROM stocks WHERE user_id = :uid", uid = session["user_id"])
    for i in range(0, len(symbols), 1):
        symbols[i] = symbols[i]["symbol"]
    print(symbols)
    shares = db.execute("SELECT shares FROM stocks WHERE user_id = :uid", uid = session["user_id"])
    for i in range(0, len(shares), 1):
        shares[i] = shares[i]["shares"]
    print(shares)
    names = []
    for symbol in symbols:
        names.append(lookup(symbol)["name"])
    print (names)
    bal1 = db.execute("SELECT cash FROM users WHERE id = :uid", uid = session["user_id"])
    bal2 = bal1[0]
    balance = bal2["cash"]
    prices = []
    for symbol in symbols:
        prices.append(lookup(symbol)["price"])
    return render_template("index.html", symbols=symbols, shares=shares, balance=balance, names=names, prices=prices)

@app.route("/buy", methods=["GET"])
@login_required
def buy():
    return render_template("buy.html")

@app.route("/buy", methods=["POST"])
@login_required
def bought():
    # Buy stocks
    num = request.form.get("stock_num")
    try:
        int(num)
    except:
        return apology("Enter a valid number of shares!")
    num = int(num)
    cross = False
    if not request.form.get("symbol"):
        return session["user_id"]
    elif not request.form.get("stock_num") or int(request.form.get("stock_num")) <= 0:
        return apology("Invalid number of stocks!")
    else:
        ans = lookup(request.form.get("symbol"))
        if ans == None:
            return apology("Enter a valid symbol")
        symbol = ans["symbol"]
        cost = ans["price"] * num
        ans1 = (db.execute("SELECT cash FROM users WHERE id=':uid'", uid = session["user_id"]))
        balance = ans1[0]["cash"]
        if balance < cost:
            return apology("You don't have enough money!")
        balance -= cost
        # If stock already exists
        stocks = db.execute("SELECT symbol FROM stocks WHERE user_id = ':uid'", uid = session["user_id"])
        for i in range(0, len(stocks), 1):
            stocks[i] = stocks[i]["symbol"]
        shares = db.execute("SELECT shares FROM stocks WHERE user_id = ':uid'", uid = session["user_id"])
        for i in range(0, len(shares), 1):
            shares[i] = shares[i]["shares"]   
        for i in range(0, len(stocks), 1):
            if symbol == stocks[i]:
                shares[i] += num
                db.execute("UPDATE stocks SET shares=':shr' WHERE symbol=:sym", shr=shares[i], sym=symbol) 
                cross = True
        db.execute("UPDATE users SET cash=':balance' WHERE id=':uid'", balance=balance, uid = session["user_id"])
        if cross == False:
            db.execute("INSERT INTO stocks(user_id, symbol, shares) VALUES (:uid, :sym, :shr)", uid = session["user_id"], sym = str((lookup(request.form.get("symbol")))["symbol"]), shr = int((request.form.get("stock_num"))))             
        return render_template("bought.html", balance=balance)
  
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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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


@app.route("/quote", methods=["GET"])
@login_required
def quote():
    return render_template("quote.html")
    
@app.route("/quote", methods=["POST"])   
@login_required
def quoted():
    """Get stock quote."""
    if not request.form.get("symbol"):
        return apology("You must give a symbol!")
    elif lookup(request.form.get("symbol")) == None:
        return apology("Please give a valid symbol!")
    else:
        ans = lookup(request.form.get("symbol"))
        return render_template("quoted.html", name=ans["name"], price=ans["price"])
    

@app.route("/register", methods=["GET"])
def render_register():
    """Register user"""
    return render_template("register.html")
    if not request.form.get("username"):
        apology("You must enter a username!")

# Checking if password has good chars.
def pw_checker(pw):
    pw_chars = list(pw)
    at_sign = 0
    dollar_sign = 0
    dot_sign = 0
    for char in pw_chars:
        if char == "@":
            at_sign += 1
        elif char == "$":
            dollar_sign += 1
        elif char == ".":
            dot_sign += 1
    if at_sign < 1 or dollar_sign < 1 or dot_sign < 1:
        return False
    else:
        return True
        
        
@app.route("/register", methods=["POST"])
def register():
    """Register user"""
    if len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) != 0:
      return apology("This username is already taken!")
    elif not request.form.get("username"):
        return apology("You did not give a username!")
    elif not request.form.get("password"):
        return apology("You did not give a password!")
    elif request.form.get("password")!=request.form.get("password_confirm"):
        return apology("Your passwords did not match!")
    if pw_checker(request.form.get("password")) == False:
        return apology("Your password did not contain all the required characters!")
    else:
        pwhash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username,hash) VALUES (:username, :hash)", username=request.form.get("username"), hash=pwhash)
        return render_template("login.html")

@app.route("/sell", methods=["GET"])
@login_required
def sell():
    symbols = db.execute("SELECT symbol FROM stocks WHERE user_id = :uid", uid = session["user_id"])
    for i in range(0, len(symbols), 1):
        symbols[i] = symbols[i]["symbol"]
    return render_template("sell.html", symbols=symbols)
    

@app.route("/sell", methods=["POST"])
@login_required
def sold():
    symbols = db.execute("SELECT symbol FROM stocks WHERE user_id = :uid", uid = session["user_id"])
    for i in range(0, len(symbols), 1):
        symbols[i] = symbols[i]["symbol"]
    shares = db.execute("SELECT shares FROM stocks WHERE user_id = :uid", uid = session["user_id"])
    for i in range(0, len(shares), 1):
        shares[i] = shares[i]["shares"]
    sharesToSell = request.form.get("shares")
    try:
        int(sharesToSell)
    except:
        return apology("Enter a valid number of shares!")
    sharesToSell = int(sharesToSell)
    sel_symb_index = symbols.index(request.form.get("symbol"))
    num_shares = shares[sel_symb_index] 
    print(num_shares)
    if sharesToSell <= 0 or sharesToSell > int(num_shares):
        return apology("Please enter a valid number of shares!")
    else:
        price = float((lookup(request.form.get("symbol")))["price"])
        bal1 = db.execute("SELECT cash FROM users WHERE id = :uid", uid = session["user_id"])
        bal2 = bal1[0]
        balance = float(bal2["cash"])
        bef_balance = balance
        balance += price * sharesToSell
        balance_change = balance - bef_balance 
        db.execute("UPDATE users SET cash = :bal WHERE id = :uid", bal = balance, uid = session["user_id"])
        num_shares -= sharesToSell
        print(num_shares)
        db.execute("UPDATE stocks SET shares = :shr WHERE symbol = :sym", shr = num_shares, sym = symbols[sel_symb_index])
        db.execute("DELETE FROM stocks WHERE shares = 0")
        return render_template("sold.html",  balance = balance, balance_change = balance_change)

@app.route("/add", methods=["GET"])
@login_required
def add():
    bal1 = db.execute("SELECT cash FROM users WHERE id = :uid", uid = session["user_id"])
    bal2 = bal1[0]
    balance = float(bal2["cash"])
    return render_template("add.html", balance=balance)

@app.route("/add", methods=["POST"])
@login_required
def added():
    value_to_add = float(request.form.get("cash_add"))
    if value_to_add < 0:
        return apology("Why would you want to decrease your balance?!")
    bal1 = db.execute("SELECT cash FROM users WHERE id = :uid", uid = session["user_id"])
    bal2 = bal1[0]
    balance = float(bal2["cash"])
    balance += value_to_add
    db.execute("UPDATE users SET cash = :bal where id = :uid", bal=balance, uid=session["user_id"])
    return redirect("/")

@app.route("/delete", methods=["GET"])
@login_required
def delete():
    return render_template("delete.html")

@app.route("/delete", methods=["POST"])
@login_required
def deleted():
    if request.form.get("delete_option") == "yes":
        db.execute("DELETE FROM users WHERE id=:uid", uid=session["user_id"])
        db.execute("DELETE FROM stocks WHERE user_id=:uid", uid=session["user_id"])
        return redirect("/login")
    else:
        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
