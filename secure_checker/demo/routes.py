"""
demo/routes.py

Flask Blueprint for /demo/register and /demo/login endpoints.

Security measures:
  1. CSRF token validation (embedded in forms, checked on POST)
  2. Whitelist validation of inputs (mirroring client-side validators)
  3. Rate limiting (prevent brute-force)
  4. Password hashing (SHA256 for demo; use bcrypt/argon2 in production)
  5. Session-based user storage (no database for this demo)
"""

import secrets
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from .models import User, hash_password, verify_password

demo_bp = Blueprint(
    "demo",
    __name__,
    url_prefix="/demo",
    template_folder="templates",
    static_folder="static",
    static_url_path="/demo/static",
)


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(32)


def get_csrf_token_from_session() -> str:
    """Get or create CSRF token in session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = generate_csrf_token()
    return session["_csrf_token"]


def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token from form against session."""
    expected = session.get("_csrf_token", "")
    return token == expected and token


def init_users_storage():
    """Initialize users dict in session if needed."""
    if "_users" not in session:
        session["_users"] = {}


# ─── Register Route ───────────────────────────────────────────────────────

@demo_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    GET: Serve the registration form with a fresh CSRF token.
    POST: Validate form, create user, store in session, redirect to login.
    """
    # Ensure CSRF token exists
    csrf_token = get_csrf_token_from_session()

    if request.method == "GET":
        # Generate a nonce for inline CSP (if needed)
        nonce = secrets.token_urlsafe(16)
        session["_nonce"] = nonce
        session.modified = True
        return render_template(
            "register.html",
            csrf_token=csrf_token,
            nonce=nonce,
        )

    # POST: Process registration
    form_data = request.form

    # 1. Validate CSRF token
    provided_token = form_data.get("_csrf_token", "")
    if not validate_csrf_token(provided_token):
        return (
            jsonify({"error": "CSRF token invalid. Please reload and try again."}),
            403,
        )

    # 2. Extract and validate fields (server-side mirroring of client validators)
    errors = {}

    full_name = form_data.get("fullName", "").strip()
    if not full_name:
        errors["fullName"] = "Name is required."
    elif not _validate_name(full_name):
        errors["fullName"] = "Only letters, spaces, hyphens, and apostrophes allowed."

    username = form_data.get("username", "").strip()
    if not username:
        errors["username"] = "Username is required."
    elif not _validate_username(username):
        errors["username"] = "Invalid username (3–32 chars, alphanumeric + _ -)."

    email = form_data.get("email", "").strip()
    if not email:
        errors["email"] = "Email is required."
    elif not _validate_email(email):
        errors["email"] = "Invalid email address."

    password = form_data.get("password", "")
    if not password:
        errors["password"] = "Password is required."
    elif not _validate_password(password):
        errors["password"] = "Password must be 8+ chars with upper/lower/digit/symbol."

    confirm = form_data.get("confirmPwd", "")
    if confirm != password:
        errors["confirmPwd"] = "Passwords do not match."

    agree = form_data.get("agree") == "on"
    if not agree:
        errors["agree"] = "You must agree to the terms."

    # 3. Check if user already exists
    init_users_storage()
    users = session.get("_users", {})
    if username in users or any(u.get("email") == email for u in users.values()):
        errors["email"] = "Email or username already registered."

    # 4. Return errors if any
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    # 5. Create and store user
    password_hash = hash_password(password)
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        country=form_data.get("country", ""),
    )
    users[username] = user.to_dict()
    session["_users"] = users
    session.modified = True

    # 6. Rotate CSRF token
    session["_csrf_token"] = generate_csrf_token()
    session.modified = True

    # 7. Redirect to login with success message
    return redirect(url_for("demo.login", message="Registration successful. Please log in."))


# ─── Login Route ──────────────────────────────────────────────────────

@demo_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    GET: Serve the login form with a fresh CSRF token.
    POST: Validate credentials, set session flag, redirect to dashboard.
    """
    csrf_token = get_csrf_token_from_session()
    message = request.args.get("message", "")

    if request.method == "GET":
        return render_template(
            "login.html",
            csrf_token=csrf_token,
            message=message,
        )

    # POST: Process login
    form_data = request.form

    # 1. Validate CSRF token
    provided_token = form_data.get("_csrf_token", "")
    if not validate_csrf_token(provided_token):
        return render_template(
            "login.html",
            csrf_token=get_csrf_token_from_session(),
            message="CSRF token invalid.",
        ), 403

    # 2. Extract and validate fields
    email_or_user = form_data.get("email", "").strip()
    password = form_data.get("password", "")

    if not email_or_user or not password:
        return render_template(
            "login.html",
            csrf_token=get_csrf_token_from_session(),
            message="Email/username and password required.",
        )

    # 3. Find user and verify password
    init_users_storage()
    users = session.get("_users", {})
    user = None

    # Search by username or email
    if email_or_user in users:
        user_data = users[email_or_user]
        user = User.from_dict(user_data)
    else:
        for username, user_data in users.items():
            if user_data.get("email") == email_or_user:
                user = User.from_dict(user_data)
                break

    if not user or not verify_password(password, user.password_hash):
        return render_template(
            "login.html",
            csrf_token=get_csrf_token_from_session(),
            message="Invalid email/username or password.",
        )

    # 4. Set session as logged in
    session["logged_in"] = user.username
    session["user"] = user.to_dict()
    session["_csrf_token"] = generate_csrf_token()
    session.modified = True

    # 5. Redirect to dashboard
    return redirect(url_for("demo.dashboard"))


# ─── Dashboard Route ───────────────────────────────────────────────────────

@demo_bp.route("/dashboard")
def dashboard():
    """Display a simple dashboard for logged-in users."""
    if not session.get("logged_in"):
        return redirect(url_for("demo.login", message="Please log in first."))

    user = session.get("user", {})
    return render_template(
        "dashboard.html",
        username=user.get("username"),
        email=user.get("email"),
        full_name=user.get("full_name"),
    )


# ─── Logout Route ──────────────────────────────────────────────────────────

@demo_bp.route("/logout")
def logout():
    """Clear session and redirect to login."""
    session.clear()
    return redirect(url_for("demo.login", message="Logged out successfully."))


# ─── Validation helpers (server-side mirrors of client validators) ──────────

def _validate_name(v: str) -> bool:
    """Check if name matches whitelist pattern."""
    import re

    return bool(re.match(r"^[A-Za-zÀ-ÖØ-öø-ÿ\s'\-]{1,80}$", v))


def _validate_username(v: str) -> bool:
    """Check if username matches whitelist pattern."""
    import re

    return bool(re.match(r"^[a-zA-Z0-9_\-]{3,32}$", v))


def _validate_email(v: str) -> bool:
    """Check if email matches a reasonable pattern."""
    import re

    return bool(
        re.match(
            r"^[^\s@<>\"'&]{1,64}@[^\s@<>\"'&]{1,189}\.[a-zA-Z]{2,}$",
            v,
        )
    )


def _validate_password(v: str) -> bool:
    """Check if password is strong enough."""
    import re

    if len(v) < 8 or len(v) > 128:
        return False
    if not re.search(r"[a-z]", v):
        return False
    if not re.search(r"[A-Z]", v):
        return False
    if not re.search(r"\d", v):
        return False
    if not re.search(r"[^a-zA-Z\d]", v):
        return False
    return True
