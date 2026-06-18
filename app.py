from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
import html
import secrets
import sqlite3


BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "misinfo_network.db"
UPLOAD_DIR = BASE_DIR / "uploads"
STATIC_DIR = BASE_DIR / "static"
IMAGE_DIR = BASE_DIR / "images"
PORT = 8000

FILTER_CATEGORY = "Misinformation Influence"

sessions = {}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db_connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def column_names(db, table):
    return [row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]


def setup_database():
    UPLOAD_DIR.mkdir(exist_ok=True)
    STATIC_DIR.mkdir(exist_ok=True)
    with db_connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT DEFAULT '',
                mobile TEXT DEFAULT '',
                dob TEXT DEFAULT '',
                gender TEXT DEFAULT '',
                address TEXT DEFAULT '',
                location TEXT DEFAULT '',
                profile_image TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'approved',
                blocked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_from TEXT NOT NULL,
                request_to TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT DEFAULT '',
                filename TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(post_id, username)
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS filter_words (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                word TEXT NOT NULL,
                post_title TEXT NOT NULL
            );
            """
        )

        # Migrate older databases from earlier versions of this app that
        # didn't have all of these columns yet.
        existing_columns = column_names(db, "users")
        migrations = {
            "status": "TEXT NOT NULL DEFAULT 'approved'",
            "blocked": "INTEGER NOT NULL DEFAULT 0",
            "email": "TEXT DEFAULT ''",
            "mobile": "TEXT DEFAULT ''",
            "dob": "TEXT DEFAULT ''",
            "gender": "TEXT DEFAULT ''",
            "address": "TEXT DEFAULT ''",
            "location": "TEXT DEFAULT ''",
            "profile_image": "TEXT DEFAULT ''",
        }
        for column, definition in migrations.items():
            if column not in existing_columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

        seed_users = [
            ("alice", "alice123", "alice@example.com", "9000000001", "1995-04-12", "Female", "12 MG Road", "Bangalore"),
            ("bob", "bob123", "bob@example.com", "9000000002", "1993-08-23", "Male", "45 Park Street", "Chennai"),
            ("charlie", "charlie123", "charlie@example.com", "9000000003", "1998-01-30", "Male", "7 Lake View", "Mumbai"),
        ]
        for username, password, email, mobile, dob, gender, address, location in seed_users:
            db.execute(
                """
                INSERT OR IGNORE INTO users
                    (username, password, email, mobile, dob, gender, address, location, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved')
                """,
                (username, password, email, mobile, dob, gender, address, location),
            )
        db.commit()


def clean(value):
    return html.escape(str(value or ""), quote=True)


def query_one(sql, params=()):
    with db_connect() as db:
        return db.execute(sql, params).fetchone()


def query_all(sql, params=()):
    with db_connect() as db:
        return db.execute(sql, params).fetchall()


def execute(sql, params=()):
    with db_connect() as db:
        db.execute(sql, params)
        db.commit()


def current_user(handler):
    cookie_header = handler.headers.get("Cookie", "")
    cookies = SimpleCookie(cookie_header)
    session_cookie = cookies.get("session_id")
    if not session_cookie:
        return None
    return sessions.get(session_cookie.value)


def create_session(username, role):
    session_id = secrets.token_hex(16)
    sessions[session_id] = {"username": username, "role": role}
    return session_id


def parse_multipart_form(rfile, content_type, content_length):
    """A tiny hand-rolled multipart/form-data parser.

    Replaces the deprecated `cgi.FieldStorage`. Good enough for this app's
    simple "a few text fields plus one optional file" forms; not meant to be
    a general-purpose MIME parser.
    """
    fields = {}
    files = {}
    if not content_type or "multipart/form-data" not in content_type or "boundary=" not in content_type:
        return fields, files

    boundary = content_type.split("boundary=", 1)[1].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary_bytes = ("--" + boundary).encode("utf-8")

    data = rfile.read(content_length)
    parts = data.split(boundary_bytes)

    for part in parts:
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue

        header_blob, sep, body = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        body = body[:-2] if body.endswith(b"\r\n") else body

        name = None
        filename = None
        for line in header_blob.decode("utf-8", errors="replace").split("\r\n"):
            if line.lower().startswith("content-disposition"):
                for piece in line.split(";"):
                    piece = piece.strip()
                    if piece.startswith("name="):
                        name = piece[len("name="):].strip('"')
                    elif piece.startswith("filename="):
                        filename = piece[len("filename="):].strip('"')

        if name is None:
            continue
        if filename is not None:
            if filename:
                files[name] = (filename, body)
        else:
            fields[name] = body.decode("utf-8", errors="replace")

    return fields, files


def save_upload(files, field_name, prefix=""):
    """Save an uploaded file (if present) to UPLOAD_DIR and return its
    stored filename, or '' if no file was uploaded."""
    if field_name not in files:
        return ""
    filename, content = files[field_name]
    safe_name = Path(filename).name
    if not safe_name:
        return ""
    stored_name = f"{prefix}{secrets.token_hex(6)}_{safe_name}"
    (UPLOAD_DIR / stored_name).write_bytes(content)
    return stored_name


def misinformation_score(text):
    """A simple, always-on heuristic shown as a badge on every post. This is
    independent of the admin-managed filter-word system (see
    run_misinformation_scan) which is the real moderation mechanism."""
    words = ["fake", "rumor", "misinformation", "harassment", "assault", "viral", "unverified"]
    lower_text = text.lower()
    return sum(1 for word in words if word in lower_text)


def run_misinformation_scan():
    """Mirrors the original A_View_Misinformation_Influence.jsp: for every
    post topic, check its comments against the admin-defined filter words
    for that topic. Any commenter whose comment contains a matching word
    gets blocked. Returns the list of newly-flagged rows for display.

    This runs fresh every time the admin opens the page, exactly like the
    original JSP did on every page load.
    """
    flagged = []
    titles = query_all("SELECT DISTINCT title FROM posts")
    for title_row in titles:
        title = title_row["title"]
        filters = query_all(
            "SELECT * FROM filter_words WHERE post_title = ?", (title,)
        )
        if not filters:
            continue
        comments = query_all(
            """
            SELECT comments.* FROM comments
            JOIN posts ON posts.id = comments.post_id
            WHERE posts.title = ?
            """,
            (title,),
        )
        for comment in comments:
            comment_lower = comment["comment"].lower()
            for word_row in filters:
                if word_row["word"].lower() in comment_lower:
                    execute(
                        "UPDATE users SET blocked = 1 WHERE username = ?",
                        (comment["username"],),
                    )
                    flagged.append(
                        {
                            "post_title": title,
                            "commenter": comment["username"],
                            "comment": comment["comment"],
                            "filter_word": word_row["word"],
                            "created_at": comment["created_at"],
                        }
                    )
                    break
    return flagged


def friendship_status(username, other_username):
    request_row = query_one(
        """
        SELECT * FROM friend_requests
        WHERE (request_from = ? AND request_to = ?)
           OR (request_from = ? AND request_to = ?)
        ORDER BY id DESC
        """,
        (username, other_username, other_username, username),
    )
    if not request_row:
        return "request"
    if request_row["status"] == "Accepted":
        return "Already Friend"
    if request_row["request_to"] == username:
        return "Accept"
    return "sent"


def get_friends(username):
    rows = query_all(
        """
        SELECT request_from, request_to FROM friend_requests
        WHERE status = 'Accepted' AND (request_from = ? OR request_to = ?)
        """,
        (username, username),
    )
    friends = []
    for row in rows:
        friends.append(row["request_to"] if row["request_from"] == username else row["request_from"])
    return friends


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def page(title, body, user=None):
    username = user["username"] if user else ""
    nav = """
        <a href="/">Home</a>
        <a href="/login/user">User Login</a>
        <a href="/login/admin">Admin Login</a>
    """
    if user and user["role"] == "user":
        nav = """
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">My Profile</a>
            <a href="/friends/list">My Friends</a>
            <a href="/friends">Find Friends</a>
            <a href="/requests">Requests</a>
            <a href="/posts">Create Post</a>
            <a href="/feed">Friend Posts</a>
            <a href="/chat">Chat</a>
            <a href="/logout">Logout</a>
        """
    if user and user["role"] == "admin":
        nav = """
            <a href="/admin">Dashboard</a>
            <a href="/admin/filters">Filter Words</a>
            <a href="/admin/misinformation">Misinformation Scan</a>
            <a href="/admin/comments">All Comments</a>
            <a href="/admin/blocked">Blocked Users</a>
            <a href="/admin/results">Results</a>
            <a href="/logout">Logout</a>
        """

    signed_in = f"<span class='signed-in'>Signed in as {clean(username)}</span>" if user else ""
    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{clean(title)}</title>
    <link rel="stylesheet" href="/static/app.css">
</head>
<body>
    <header class="topbar">
        <div>
            <h1>Activity Minimization of Misinformation Influence in Online Social Network</h1>
        </div>
        {signed_in}
    </header>
    <nav class="nav">{nav}</nav>
    <main class="container">{body}</main>
</body>
</html>"""


def profile_table_html(user_row):
    photo_block = "<p class='muted'>No photo uploaded.</p>"
    if user_row["profile_image"]:
        photo_block = f"<img class='avatar-large' src='/uploads/{quote(user_row['profile_image'])}' alt='Profile photo'>"
    return f"""
    <div class="profile-card">
        {photo_block}
        <table>
            <tr><th>Username</th><td>{clean(user_row["username"])}</td></tr>
            <tr><th>Email</th><td>{clean(user_row["email"])}</td></tr>
            <tr><th>Mobile</th><td>{clean(user_row["mobile"])}</td></tr>
            <tr><th>Date of Birth</th><td>{clean(user_row["dob"])}</td></tr>
            <tr><th>Gender</th><td>{clean(user_row["gender"])}</td></tr>
            <tr><th>Address</th><td>{clean(user_row["address"])}</td></tr>
            <tr><th>Location</th><td>{clean(user_row["location"])}</td></tr>
            <tr><th>Status</th><td>{clean(user_row["status"])}</td></tr>
            <tr><th>Access</th><td>{'Blocked' if user_row["blocked"] else 'Active'}</td></tr>
        </table>
    </div>
    """


def post_card(post, viewer_username, return_to="feed"):
    score = misinformation_score(post["description"])
    label = "Needs review" if score else "Normal"
    file_block = ""
    if post["filename"]:
        file_url = f"/uploads/{quote(post['filename'])}"
        file_name = clean(post["filename"])
        image_types = (".png", ".jpg", ".jpeg", ".gif", ".webp")
        if post["filename"].lower().endswith(image_types):
            file_block = f"""
            <figure class="upload-preview">
                <img src="{file_url}" alt="Uploaded file for {clean(post['title'])}">
                <figcaption>{file_name}</figcaption>
            </figure>
            """
        else:
            file_block = f'<p><a class="file-link" href="{file_url}">Open uploaded file: {file_name}</a></p>'

    like_count = query_one("SELECT COUNT(*) AS total FROM likes WHERE post_id = ?", (post["id"],))["total"]
    already_liked = query_one(
        "SELECT id FROM likes WHERE post_id = ? AND username = ?", (post["id"], viewer_username)
    )
    like_label = "Unlike" if already_liked else "Like"

    comments = query_all("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at", (post["id"],))
    comment_html = "".join(
        f"<p class='comment'><strong>{clean(c['username'])}:</strong> {clean(c['comment'])}</p>" for c in comments
    ) or "<p class='comment muted'>No comments yet.</p>"

    return f"""
    <article class="card post">
        <h3>{clean(post["title"])}</h3>
        <p><strong>By:</strong> {clean(post["sender"])} | <strong>Date:</strong> {clean(post["created_at"])}</p>
        <p>{clean(post["description"])}</p>
        <p><strong>Category:</strong> {clean(post["category"]) or "General"}</p>
        <span class="badge">{label}</span>
        {file_block}
        <div class="post-actions">
            <a class="button secondary" href="/post?id={post['id']}">View Details</a>
            <form method="post" action="/post/like" style="display:inline">
                <input type="hidden" name="post_id" value="{post['id']}">
                <input type="hidden" name="return_to" value="{return_to}">
                <button>{like_label} ({like_count})</button>
            </form>
        </div>
        <div class="comments">
            {comment_html}
            <form method="post" action="/post/comment" class="comment-form">
                <input type="hidden" name="post_id" value="{post['id']}">
                <input type="hidden" name="return_to" value="{return_to}">
                <input name="comment" placeholder="Write a comment..." required>
                <button>Comment</button>
            </form>
        </div>
    </article>
    """


def admin_post_row(post):
    score = misinformation_score(post["description"])
    review = "Needs review" if score else "Normal"
    file_cell = "No file"
    if post["filename"]:
        file_url = f"/uploads/{quote(post['filename'])}"
        file_cell = f'<a href="{file_url}">{clean(post["filename"])}</a>'
    return f"""
    <tr>
        <td>{clean(post["sender"])}</td>
        <td>{clean(post["title"])}</td>
        <td>{clean(post["category"]) or "General"}</td>
        <td>{review}</td>
        <td>{file_cell}</td>
        <td>{clean(post["created_at"])}</td>
        <td>
            <a href="/admin/post?id={post['id']}">View</a>
            <form method="post" action="/admin/post/delete" onsubmit="return confirm('Remove this post?');" style="display:inline">
                <input type="hidden" name="post_id" value="{post['id']}">
                <button class="danger">Remove</button>
            </form>
        </td>
    </tr>
    """


def bar_chart_html(rows, label_key, value_key, color="#1976d2"):
    """A plain CSS bar chart (no JS charting library needed) — replaces the
    original's jscharts.js graphs with the same information."""
    if not rows:
        return "<p class='muted'>No data yet.</p>"
    max_value = max(row[value_key] for row in rows) or 1
    bars = ""
    for row in rows:
        width_pct = max(4, round((row[value_key] / max_value) * 100))
        bars += f"""
        <div class="bar-row">
            <span class="bar-label">{clean(row[label_key])}</span>
            <div class="bar-track">
                <div class="bar-fill" style="width:{width_pct}%; background:{color};">{row[value_key]}</div>
            </div>
        </div>
        """
    return f"<div class='bar-chart'>{bars}</div>"


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class MisinfoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/static/"):
            return self.serve_file(STATIC_DIR, path.replace("/static/", "", 1))
        if path.startswith("/images/"):
            return self.serve_file(IMAGE_DIR, path.replace("/images/", "", 1))
        if path.startswith("/uploads/"):
            return self.serve_file(UPLOAD_DIR, path.replace("/uploads/", "", 1))

        user = current_user(self)
        routes = {
            "/": lambda: self.home(user),
            "/login/user": lambda: self.login_form("user", user),
            "/login/admin": lambda: self.login_form("admin", user),
            "/register": lambda: self.register_form(user),
            "/logout": self.logout,
            "/dashboard": lambda: self.user_dashboard(user),
            "/profile": lambda: self.profile_page(user),
            "/friends": lambda: self.friends_page(user, query),
            "/friends/list": lambda: self.friends_list_page(user),
            "/requests": lambda: self.requests_page(user),
            "/posts": lambda: self.posts_page(user),
            "/feed": lambda: self.feed_page(user),
            "/chat": lambda: self.chat_page(user, query),
            "/admin": lambda: self.admin_page(user),
            "/admin/filters": lambda: self.admin_filters_page(user),
            "/admin/misinformation": lambda: self.admin_misinformation_page(user),
            "/admin/comments": lambda: self.admin_comments_page(user, query),
            "/admin/blocked": lambda: self.admin_blocked_page(user),
            "/admin/results": lambda: self.admin_results_page(user),
            "/admin/profile": lambda: self.admin_profile_page(user, query),
            "/admin/post": lambda: self.admin_post_detail_page(user, query),
            "/post": lambda: self.user_post_detail_page(user, query),
        }
        handler = routes.get(path)
        if handler:
            return handler()

        self.send_html("Not found", "<h2>Page not found</h2>", HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        routes = {
            "/login/user": self.login_user,
            "/login/admin": self.login_admin,
            "/register": self.register_user,
            "/friend/request": self.send_friend_request,
            "/friend/accept": self.accept_friend_request,
            "/posts": self.create_post,
            "/post/like": self.toggle_like,
            "/post/comment": self.add_comment,
            "/chat/send": self.send_chat_message,
            "/admin/registration/decide": self.admin_decide_registration,
            "/admin/user/block": self.admin_toggle_block,
            "/admin/user/delete": self.admin_delete_user,
            "/admin/post/delete": self.admin_delete_post,
            "/admin/filters/add": self.admin_add_filter,
        }
        handler = routes.get(path)
        if handler:
            return handler()
        self.redirect("/")

    # -- low level helpers ---------------------------------------------

    def read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        return {key: values[0] for key, values in parse_qs(body).items()}

    def send_html(self, title, body, status=HTTPStatus.OK, user=None, cookie=None):
        content = page(title, body, user).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location, cookie=None):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def serve_file(self, base_dir, requested_name):
        safe_name = Path(unquote(requested_name)).name
        path = base_dir / safe_name
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = "text/plain"
        if path.suffix == ".css":
            content_type = "text/css"
        elif path.suffix in [".jpg", ".jpeg"]:
            content_type = "image/jpeg"
        elif path.suffix == ".png":
            content_type = "image/png"
        elif path.suffix == ".gif":
            content_type = "image/gif"
        elif path.suffix == ".pdf":
            content_type = "application/pdf"

        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def require_user(self, user, role="user"):
        if not user or user["role"] != role:
            self.redirect(f"/login/{role}")
            return False
        if role == "user":
            # Re-check live status: an admin may have blocked / unapproved
            # this account after the session cookie was issued.
            db_user = query_one("SELECT blocked, status FROM users WHERE username = ?", (user["username"],))
            if not db_user or db_user["blocked"] or db_user["status"] != "approved":
                self.login_form(
                    "user",
                    None,
                    "Your account is blocked or no longer approved. Please contact the admin.",
                )
                return False
        return True

    # -- public pages -----------------------------------------------------

    def home(self, user):
        body = """
        <section class="hero">
            <img src="/images/img1.jpg" alt="Social network">
            <div>
                <h2>Simple social network </h2>
                <p>This web application combines social networking features with misinformation detection. Users can register, add friends, create posts, like and comment on posts, and chat with friends. An administrator reviews and approves user registrations and can manage all users, posts, and comments</p>
                <p>The admin can configure filter words for different topics and run a scan that checks user comments for misinformation. Users identified as spreading misinformation can be blocked automatically, helping reduce the spread of false information across the platform.</p>
                <div class="actions">
                    <a class="button" href="/login/user">User Login</a>
                    <a class="button secondary" href="/login/admin">Admin Login</a>
                </div>
            </div>
        </section>
        """
        self.send_html("Home", body, user=user)

    def login_form(self, role, user, message=""):
        username_label = "Admin Name" if role == "admin" else "User Name"
        register_link = "" if role == "admin" else '<p>New user? <a href="/register">Register here</a></p>'
        body = f"""
        <section class="panel narrow">
            <h2>{role.title()} Login</h2>
            <p class="message">{clean(message)}</p>
            <form method="post">
                <label>{username_label}</label>
                <input name="username" required>
                <label>Password</label>
                <input name="password" type="password" required>
                <button type="submit">Login</button>
            </form>
            {register_link}
        </section>
        """
        self.send_html(f"{role.title()} Login", body, user=user)

    def login_user(self):
        form = self.read_form()
        user_row = query_one(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (form.get("username", ""), form.get("password", "")),
        )
        if not user_row:
            return self.login_form("user", None, "Invalid user name or password.")
        if user_row["blocked"]:
            return self.login_form("user", None, "Your account has been blocked by the admin.")
        if user_row["status"] == "pending":
            return self.login_form("user", None, "Your registration is still awaiting admin approval.")
        if user_row["status"] == "rejected":
            return self.login_form("user", None, "Your registration request was rejected by the admin.")
        session_id = create_session(user_row["username"], "user")
        self.redirect("/dashboard", f"session_id={session_id}; Path=/; HttpOnly")

    def login_admin(self):
        form = self.read_form()
        if form.get("username") == "admin" and form.get("password") == "admin":
            session_id = create_session("admin", "admin")
            return self.redirect("/admin", f"session_id={session_id}; Path=/; HttpOnly")
        self.login_form("admin", None, "Use admin / admin for this demo.")

    def register_form(self, user, message=""):
        body = f"""
        <section class="panel narrow">
            <h2>User Registration</h2>
            <p class="message">{clean(message)}</p>
            <p>New accounts must be approved by the admin before you can log in.</p>
            <form method="post" enctype="multipart/form-data">
                <label>User Name</label>
                <input name="username" required>
                <label>Password</label>
                <input name="password" type="password" required>
                <label>Email</label>
                <input name="email" type="email">
                <label>Mobile</label>
                <input name="mobile">
                <label>Date of Birth</label>
                <input name="dob" type="date">
                <label>Gender</label>
                <select name="gender">
                    <option value="">--Select--</option>
                    <option>Male</option>
                    <option>Female</option>
                    <option>Other</option>
                </select>
                <label>Address</label>
                <input name="address">
                <label>Location</label>
                <input name="location">
                <label>Profile Photo (optional)</label>
                <input name="photo" type="file">
                <button type="submit">Create Account</button>
            </form>
        </section>
        """
        self.send_html("Register", body, user=user)

    def register_user(self):
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))
        fields, files = parse_multipart_form(self.rfile, content_type, content_length)

        username = fields.get("username", "").strip()
        if not username or not fields.get("password"):
            return self.register_form(None, "Username and password are required.")

        profile_image = save_upload(files, "photo", prefix="avatar_")

        try:
            execute(
                """
                INSERT INTO users
                    (username, password, email, mobile, dob, gender, address, location, profile_image, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    username,
                    fields.get("password", ""),
                    fields.get("email", ""),
                    fields.get("mobile", ""),
                    fields.get("dob", ""),
                    fields.get("gender", ""),
                    fields.get("address", ""),
                    fields.get("location", ""),
                    profile_image,
                ),
            )
        except sqlite3.IntegrityError:
            return self.register_form(None, "That username already exists.")
        self.login_form(
            "user",
            None,
            "Registration submitted! Please wait for admin approval before logging in.",
        )

    def logout(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        session_cookie = cookies.get("session_id")
        if session_cookie:
            sessions.pop(session_cookie.value, None)
        self.redirect("/", "session_id=deleted; Path=/; Max-Age=0")

    # -- user pages ---------------------------------------------------

    def user_dashboard(self, user):
        if not self.require_user(user):
            return
        body = f"""
        <section class="panel">
            <h2>Welcome, {clean(user["username"])}</h2>
            <div class="grid">
                <a class="tile" href="/profile">My profile</a>
                <a class="tile" href="/friends/list">My friends</a>
                <a class="tile" href="/friends">Search friends</a>
                <a class="tile" href="/requests">View friend requests</a>
                <a class="tile" href="/posts">Create post</a>
                <a class="tile" href="/feed">View friends' posts</a>
                <a class="tile" href="/chat">Chat with friends</a>
            </div>
        </section>
        """
        self.send_html("Dashboard", body, user=user)

    def profile_page(self, user):
        if not self.require_user(user):
            return
        row = query_one("SELECT * FROM users WHERE username = ?", (user["username"],))
        body = f"""
        <section class="panel">
            <h2>My Profile</h2>
            {profile_table_html(row)}
        </section>
        """
        self.send_html("My Profile", body, user=user)

    def friends_page(self, user, query):
        if not self.require_user(user):
            return
        keyword = query.get("q", [""])[0]
        rows = []
        if keyword:
            rows = query_all(
                "SELECT * FROM users WHERE username LIKE ? AND username != ? AND status = 'approved' AND blocked = 0 ORDER BY username",
                (f"%{keyword}%", user["username"]),
            )

        cards = ""
        for row in rows:
            status = friendship_status(user["username"], row["username"])
            action = ""
            if status == "request":
                action = f"""
                <form method="post" action="/friend/request">
                    <input type="hidden" name="request_to" value="{clean(row["username"])}">
                    <button>Send Request</button>
                </form>
                """
            cards += f"""
            <article class="card">
                <h3>{clean(row["username"])}</h3>
                <p>{clean(row["location"]) or "Location unknown"}</p>
                <strong>{clean(status)}</strong>
                {action}
            </article>
            """
        if keyword and not cards:
            cards = f"<p>No users found for {clean(keyword)}.</p>"

        body = f"""
        <section class="panel">
            <h2>Find Friends</h2>
            <form method="get" class="search">
                <input name="q" value="{clean(keyword)}" placeholder="Search by username">
                <button>Search</button>
            </form>
            <div class="cards">{cards}</div>
        </section>
        """
        self.send_html("Find Friends", body, user=user)

    def friends_list_page(self, user):
        if not self.require_user(user):
            return
        friends = get_friends(user["username"])
        if not friends:
            body = """
            <section class="panel">
                <h2>My Friends</h2>
                <p>You have no friends yet. Use <a href="/friends">Find Friends</a> to send requests.</p>
            </section>
            """
            return self.send_html("My Friends", body, user=user)

        placeholders = ",".join("?" for _ in friends)
        rows = query_all(
            f"SELECT username, location, profile_image FROM users WHERE username IN ({placeholders}) ORDER BY username",
            friends,
        )
        cards = "".join(
            f"""
            <article class="card">
                {"<img class='avatar-small' src='/uploads/" + quote(row['profile_image']) + "' alt=''>" if row['profile_image'] else ""}
                <h3>{clean(row["username"])}</h3>
                <p>{clean(row["location"]) or "Location unknown"}</p>
                <a class="button" href="/chat?with={quote(row['username'])}">Chat</a>
            </article>
            """
            for row in rows
        )
        body = f"""
        <section class="panel">
            <h2>My Friends</h2>
            <div class="cards">{cards}</div>
        </section>
        """
        self.send_html("My Friends", body, user=user)

    def send_friend_request(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        form = self.read_form()
        target = form.get("request_to", "")
        if target and friendship_status(user["username"], target) == "request":
            execute(
                "INSERT INTO friend_requests (request_from, request_to, status) VALUES (?, ?, ?)",
                (user["username"], target, "waiting"),
            )
        self.redirect("/friends")

    def requests_page(self, user):
        if not self.require_user(user):
            return
        rows = query_all(
            "SELECT * FROM friend_requests WHERE request_to = ? AND status = 'waiting' ORDER BY created_at DESC",
            (user["username"],),
        )
        cards = ""
        for row in rows:
            cards += f"""
            <article class="card">
                <h3>{clean(row["request_from"])}</h3>
                <p>Sent on {clean(row["created_at"])}</p>
                <form method="post" action="/friend/accept">
                    <input type="hidden" name="request_id" value="{row["id"]}">
                    <button>Accept</button>
                </form>
            </article>
            """
        if not cards:
            cards = "<p>No pending friend requests.</p>"
        self.send_html("Requests", f"<section class='panel'><h2>Friend Requests</h2><div class='cards'>{cards}</div></section>", user=user)

    def accept_friend_request(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        form = self.read_form()
        execute(
            "UPDATE friend_requests SET status = 'Accepted' WHERE id = ? AND request_to = ?",
            (form.get("request_id", ""), user["username"]),
        )
        self.redirect("/requests")

    def posts_page(self, user, message=""):
        if not self.require_user(user):
            return
        posts = query_all("SELECT * FROM posts WHERE sender = ? ORDER BY created_at DESC", (user["username"],))
        user_posts = "".join(post_card(post, user["username"], "posts") for post in posts) or "<p>You have not created any posts yet.</p>"
        body = f"""
        <section class="panel">
            <h2>Create Post</h2>
            <p class="message">{clean(message)}</p>
            <form method="post" enctype="multipart/form-data">
                <label>Post Title / Topic</label>
                <input name="title" required>
                <label>Category / Use</label>
                <input name="category" placeholder="news, product, awareness...">
                <label>Description</label>
                <textarea name="description" rows="8" required></textarea>
                <label>Optional file or image</label>
                <input name="upload" type="file">
                <button type="submit">Post</button>
            </form>
            <h3>Your Posts</h3>
            <div class="cards">{user_posts}</div>
        </section>
        """
        self.send_html("Create Post", body, user=user)

    def create_post(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))
        fields, files = parse_multipart_form(self.rfile, content_type, content_length)

        title = fields.get("title", "")
        description = fields.get("description", "")
        category = fields.get("category", "")
        saved_name = save_upload(files, "upload")

        execute(
            "INSERT INTO posts (sender, title, description, category, filename) VALUES (?, ?, ?, ?, ?)",
            (user["username"], title, description, category, saved_name),
        )
        self.posts_page(user, "Posted successfully.")

    def feed_page(self, user):
        if not self.require_user(user):
            return
        friends = get_friends(user["username"])
        if not friends:
            body = "<section class='panel'><h2>Friend Posts</h2><p>Add friends first to see their posts.</p></section>"
            return self.send_html("Friend Posts", body, user=user)

        placeholders = ",".join("?" for _ in friends)
        posts = query_all(
            f"SELECT * FROM posts WHERE sender IN ({placeholders}) ORDER BY created_at DESC",
            friends,
        )
        cards = "".join(post_card(post, user["username"], "feed") for post in posts) or "<p>Your friends have not posted yet.</p>"
        self.send_html("Friend Posts", f"<section class='panel'><h2>Friend Posts</h2><div class='cards'>{cards}</div></section>", user=user)

    def toggle_like(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        form = self.read_form()
        post_id = form.get("post_id", "")
        return_to = form.get("return_to", "feed")
        existing = query_one(
            "SELECT id FROM likes WHERE post_id = ? AND username = ?", (post_id, user["username"])
        )
        if existing:
            execute("DELETE FROM likes WHERE id = ?", (existing["id"],))
        else:
            execute("INSERT INTO likes (post_id, username) VALUES (?, ?)", (post_id, user["username"]))
        self.redirect(f"/{return_to}")

    def add_comment(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        form = self.read_form()
        post_id = form.get("post_id", "")
        comment_text = form.get("comment", "").strip()
        return_to = form.get("return_to", "feed")
        if comment_text:
            execute(
                "INSERT INTO comments (post_id, username, comment) VALUES (?, ?, ?)",
                (post_id, user["username"], comment_text),
            )
        self.redirect(f"/{return_to}")

    def chat_page(self, user, query):
        if not self.require_user(user):
            return
        other = query.get("with", [""])[0]
        friends = get_friends(user["username"])

        if not friends:
            body = "<section class='panel'><h2>Chat</h2><p>Add friends first to start chatting.</p></section>"
            return self.send_html("Chat", body, user=user)

        friend_rows = query_all(
            f"SELECT username FROM users WHERE username IN ({','.join('?' for _ in friends)}) ORDER BY username",
            friends,
        )
        friend_links = "".join(
            f"""<a class="tile{' active' if row['username'] == other else ''}" href="/chat?with={quote(row['username'])}">{clean(row['username'])}</a>"""
            for row in friend_rows
        )

        conversation_html = "<p>Select a friend to start chatting.</p>"
        if other in friends:
            messages = query_all(
                """
                SELECT * FROM messages
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                ORDER BY created_at
                """,
                (user["username"], other, other, user["username"]),
            )
            bubbles = "".join(
                f"""
                <p class="chat-bubble {'mine' if m['sender'] == user['username'] else 'theirs'}">
                    <strong>{clean(m['sender'])}:</strong> {clean(m['message'])}
                    <span class="chat-time">{clean(m['created_at'])}</span>
                </p>
                """
                for m in messages
            ) or "<p>No messages yet. Say hello!</p>"
            conversation_html = f"""
            <div class="chat-window">{bubbles}</div>
            <form method="post" action="/chat/send" class="chat-form">
                <input type="hidden" name="to" value="{clean(other)}">
                <input name="message" placeholder="Type a message..." required>
                <button>Send</button>
            </form>
            """

        body = f"""
        <section class="panel">
            <h2>Chat</h2>
            <div class="chat-layout">
                <nav class="chat-friends">{friend_links}</nav>
                <div class="chat-main">{conversation_html}</div>
            </div>
        </section>
        """
        self.send_html("Chat", body, user=user)

    def send_chat_message(self):
        user = current_user(self)
        if not self.require_user(user):
            return
        form = self.read_form()
        to = form.get("to", "")
        message_text = form.get("message", "").strip()
        if message_text and to in get_friends(user["username"]):
            execute(
                "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                (user["username"], to, message_text),
            )
        self.redirect(f"/chat?with={quote(to)}")

    # -- admin pages ----------------------------------------------------

    def admin_page(self, user):
        if not self.require_user(user, "admin"):
            return
        pending_users = query_all("SELECT * FROM users WHERE status = 'pending' ORDER BY id DESC")
        all_users = query_all("SELECT * FROM users ORDER BY username")
        requests = query_all("SELECT * FROM friend_requests ORDER BY created_at DESC")
        posts = query_all("SELECT * FROM posts ORDER BY created_at DESC")
        total_users = query_one("SELECT COUNT(*) AS total FROM users")["total"]
        total_posts = query_one("SELECT COUNT(*) AS total FROM posts")["total"]
        total_requests = query_one("SELECT COUNT(*) AS total FROM friend_requests")["total"]
        accepted_requests = query_one("SELECT COUNT(*) AS total FROM friend_requests WHERE status = 'Accepted'")["total"]
        blocked_count = query_one("SELECT COUNT(*) AS total FROM users WHERE blocked = 1")["total"]

        pending_rows = "".join(
            f"""
            <tr>
                <td><a href="/admin/profile?username={quote(u['username'])}">{clean(u['username'])}</a></td>
                <td>{clean(u['email'])}</td>
                <td>
                    <form method="post" action="/admin/registration/decide" style="display:inline">
                        <input type="hidden" name="username" value="{clean(u['username'])}">
                        <input type="hidden" name="action" value="approve">
                        <button>Approve</button>
                    </form>
                    <form method="post" action="/admin/registration/decide" style="display:inline">
                        <input type="hidden" name="username" value="{clean(u['username'])}">
                        <input type="hidden" name="action" value="reject">
                        <button class="danger">Reject</button>
                    </form>
                </td>
            </tr>
            """
            for u in pending_users
        ) or "<tr><td colspan='3'>No pending registrations.</td></tr>"

        user_rows = "".join(
            f"""
            <tr>
                <td><a href="/admin/profile?username={quote(u['username'])}">{clean(u['username'])}</a></td>
                <td>{clean(u['status'])}</td>
                <td>{'Blocked' if u['blocked'] else 'Active'}</td>
                <td>
                    <form method="post" action="/admin/user/block" style="display:inline">
                        <input type="hidden" name="username" value="{clean(u['username'])}">
                        <input type="hidden" name="return_to" value="/admin">
                        <button>{'Unblock' if u['blocked'] else 'Block'}</button>
                    </form>
                    <form method="post" action="/admin/user/delete" style="display:inline" onsubmit="return confirm('Delete this user and all of their data?');">
                        <input type="hidden" name="username" value="{clean(u['username'])}">
                        <button class="danger">Delete</button>
                    </form>
                </td>
            </tr>
            """
            for u in all_users
        ) or "<tr><td colspan='4'>No users yet.</td></tr>"

        request_rows = "".join(
            f"<tr><td>{clean(r['request_from'])}</td><td>{clean(r['request_to'])}</td><td>{clean(r['status'])}</td><td>{clean(r['created_at'])}</td></tr>"
            for r in requests
        ) or "<tr><td colspan='4'>No requests yet.</td></tr>"

        post_rows = "".join(admin_post_row(post) for post in posts) or "<tr><td colspan='7'>No posts yet.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>Admin Dashboard</h2>
            <div class="stats">
                <div><strong>{total_users}</strong><span>Users</span></div>
                <div><strong>{total_posts}</strong><span>Posts</span></div>
                <div><strong>{total_requests}</strong><span>Requests</span></div>
                <div><strong>{accepted_requests}</strong><span>Accepted</span></div>
                <div><strong>{blocked_count}</strong><span>Blocked</span></div>
            </div>

            <div class="grid">
                <a class="tile" href="/admin/filters">Manage filter words</a>
                <a class="tile" href="/admin/misinformation">Run misinformation scan</a>
                <a class="tile" href="/admin/comments">Browse all comments</a>
                <a class="tile" href="/admin/blocked">View blocked users</a>
                <a class="tile" href="/admin/results">View results charts</a>
            </div>

            <h3>Pending Registrations</h3>
            <table><tr><th>Username</th><th>Email</th><th>Decision</th></tr>{pending_rows}</table>

            <h3>Manage Users</h3>
            <table><tr><th>Username</th><th>Status</th><th>Access</th><th>Actions</th></tr>{user_rows}</table>

            <h3>All Friend Requests and Responses</h3>
            <table><tr><th>From</th><th>To</th><th>Status</th><th>Date & Time</th></tr>{request_rows}</table>

            <h3>All Posts</h3>
            <table><tr><th>User</th><th>Title</th><th>Category</th><th>Review</th><th>File</th><th>Date & Time</th><th>Actions</th></tr>{post_rows}</table>
        </section>
        """
        self.send_html("Admin", body, user=user)

    def admin_profile_page(self, user, query):
        if not self.require_user(user, "admin"):
            return
        username = query.get("username", [""])[0]
        row = query_one("SELECT * FROM users WHERE username = ?", (username,))
        if not row:
            return self.send_html("Admin", "<section class='panel'><p>User not found.</p></section>", user=user)
        body = f"""
        <section class="panel">
            <h2>{clean(username)}'s Profile</h2>
            {profile_table_html(row)}
            <p><a href="/admin">&laquo; Back to Admin Dashboard</a></p>
        </section>
        """
        self.send_html(f"{username}'s Profile", body, user=user)

    def admin_blocked_page(self, user):
        if not self.require_user(user, "admin"):
            return
        rows = query_all("SELECT * FROM users WHERE blocked = 1 ORDER BY username")
        table_rows = "".join(
            f"""
            <tr>
                <td><a href="/admin/profile?username={quote(r['username'])}">{clean(r['username'])}</a></td>
                <td>{clean(r['email'])}</td>
                <td>
                    <form method="post" action="/admin/user/block">
                        <input type="hidden" name="username" value="{clean(r['username'])}">
                        <input type="hidden" name="return_to" value="/admin/blocked">
                        <button>Unblock</button>
                    </form>
                </td>
            </tr>
            """
            for r in rows
        ) or "<tr><td colspan='3'>No blocked users.</td></tr>"
        body = f"""
        <section class="panel">
            <h2>Blocked Users</h2>
            <table><tr><th>Username</th><th>Email</th><th>Action</th></tr>{table_rows}</table>
        </section>
        """
        self.send_html("Blocked Users", body, user=user)

    def admin_comments_page(self, user, query):
        if not self.require_user(user, "admin"):
            return
        title_filter = query.get("title", [""])[0]
        titles = query_all("SELECT DISTINCT title FROM posts ORDER BY title")
        options = "<option value=''>All topics</option>" + "".join(
            f"<option value='{clean(t['title'])}'{' selected' if t['title'] == title_filter else ''}>{clean(t['title'])}</option>"
            for t in titles
        )

        if title_filter:
            rows = query_all(
                """
                SELECT comments.*, posts.title AS post_title FROM comments
                JOIN posts ON posts.id = comments.post_id
                WHERE posts.title = ?
                ORDER BY comments.created_at DESC
                """,
                (title_filter,),
            )
        else:
            rows = query_all(
                """
                SELECT comments.*, posts.title AS post_title FROM comments
                JOIN posts ON posts.id = comments.post_id
                ORDER BY comments.created_at DESC
                """
            )

        table_rows = "".join(
            f"<tr><td>{clean(r['post_title'])}</td><td>{clean(r['username'])}</td><td>{clean(r['comment'])}</td><td>{clean(r['created_at'])}</td></tr>"
            for r in rows
        ) or "<tr><td colspan='4'>No comments yet.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>All Comments</h2>
            <form method="get" class="search">
                <select name="title" onchange="this.form.submit()">{options}</select>
            </form>
            <table><tr><th>Post Topic</th><th>Commenter</th><th>Comment</th><th>Date & Time</th></tr>{table_rows}</table>
        </section>
        """
        self.send_html("All Comments", body, user=user)

    def admin_filters_page(self, user, message=""):
        if not self.require_user(user, "admin"):
            return
        titles = query_all("SELECT DISTINCT title FROM posts ORDER BY title")
        title_options = "".join(f"<option>{clean(t['title'])}</option>" for t in titles) or "<option>No posts yet</option>"

        filters = query_all("SELECT * FROM filter_words ORDER BY id DESC")
        filter_rows = "".join(
            f"<tr><td>{clean(f['category'])}</td><td>{clean(f['word'])}</td><td>{clean(f['post_title'])}</td></tr>"
            for f in filters
        ) or "<tr><td colspan='3'>No filter words added yet.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>Misinformation Filter Words</h2>
            <p class="message">{clean(message)}</p>
            <p>Add a word or phrase to watch for in comments on a specific post topic. When the misinformation scan runs, any commenter whose comment contains a matching word is automatically blocked.</p>
            <form method="post" action="/admin/filters/add">
                <label>Post Topic</label>
                <select name="post_title">{title_options}</select>
                <label>Filter Category</label>
                <input name="category" value="{clean(FILTER_CATEGORY)}" readonly>
                <label>Filter Word</label>
                <input name="word" required>
                <button type="submit">Add Filter Word</button>
            </form>
            <h3>Existing Filter Words</h3>
            <table><tr><th>Category</th><th>Word</th><th>Post Topic</th></tr>{filter_rows}</table>
        </section>
        """
        self.send_html("Filter Words", body, user=user)

    def admin_add_filter(self):
        user = current_user(self)
        if not self.require_user(user, "admin"):
            return
        form = self.read_form()
        word = form.get("word", "").strip()
        post_title = form.get("post_title", "").strip()
        if word and post_title:
            execute(
                "INSERT INTO filter_words (category, word, post_title) VALUES (?, ?, ?)",
                (FILTER_CATEGORY, word, post_title),
            )
            return self.admin_filters_page(user, "Filter word added.")
        self.admin_filters_page(user, "Please choose a post topic and enter a word.")

    def admin_misinformation_page(self, user):
        if not self.require_user(user, "admin"):
            return
        flagged = run_misinformation_scan()
        rows = "".join(
            f"""
            <tr>
                <td>{clean(f['post_title'])}</td>
                <td>{clean(f['commenter'])}</td>
                <td>{clean(f['comment'])}</td>
                <td>{clean(f['filter_word'])}</td>
                <td>{clean(f['created_at'])}</td>
            </tr>
            """
            for f in flagged
        ) or "<tr><td colspan='5'>No comments matched a filter word this run.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>Misinformation Influence Scan</h2>
            <p>This scans every comment against the filter words you've configured for that post's topic. Any commenter who matches is blocked immediately. Re-run any time by reloading this page.</p>
            <table><tr><th>Post Topic</th><th>Commenter (blocked)</th><th>Comment</th><th>Matched Word</th><th>Date & Time</th></tr>{rows}</table>
            <p><a href="/admin/filters">Manage filter words</a> &middot; <a href="/admin/blocked">View blocked users</a></p>
        </section>
        """
        self.send_html("Misinformation Scan", body, user=user)

    def admin_results_page(self, user):
        if not self.require_user(user, "admin"):
            return
        comments_per_user = query_all(
            "SELECT username, COUNT(*) AS total FROM comments GROUP BY username ORDER BY total DESC"
        )
        posts_per_user = query_all(
            "SELECT sender AS username, COUNT(*) AS total FROM posts GROUP BY sender ORDER BY total DESC"
        )
        body = f"""
        <section class="panel">
            <h2>Results</h2>
            <h3>Comments per User</h3>
            {bar_chart_html(comments_per_user, "username", "total", color="#1976d2")}
            <h3>Posts per User</h3>
            {bar_chart_html(posts_per_user, "username", "total", color="#37474f")}
        </section>
        """
        self.send_html("Results", body, user=user)

    def admin_decide_registration(self):
        user = current_user(self)
        if not self.require_user(user, "admin"):
            return
        form = self.read_form()
        username = form.get("username", "")
        action = form.get("action", "")
        new_status = "approved" if action == "approve" else "rejected"
        execute("UPDATE users SET status = ? WHERE username = ?", (new_status, username))
        self.redirect("/admin")

    def admin_toggle_block(self):
        user = current_user(self)
        if not self.require_user(user, "admin"):
            return
        form = self.read_form()
        username = form.get("username", "")
        return_to = form.get("return_to", "/admin")
        row = query_one("SELECT blocked FROM users WHERE username = ?", (username,))
        if row:
            new_value = 0 if row["blocked"] else 1
            execute("UPDATE users SET blocked = ? WHERE username = ?", (new_value, username))
        self.redirect(return_to)

    def admin_delete_user(self):
        user = current_user(self)
        if not self.require_user(user, "admin"):
            return
        form = self.read_form()
        username = form.get("username", "")
        with db_connect() as db:
            db.execute("DELETE FROM posts WHERE sender = ?", (username,))
            db.execute("DELETE FROM friend_requests WHERE request_from = ? OR request_to = ?", (username, username))
            db.execute("DELETE FROM likes WHERE username = ?", (username,))
            db.execute("DELETE FROM comments WHERE username = ?", (username,))
            db.execute("DELETE FROM messages WHERE sender = ? OR receiver = ?", (username, username))
            db.execute("DELETE FROM users WHERE username = ?", (username,))
            db.commit()
        self.redirect("/admin")

    def admin_delete_post(self):
        user = current_user(self)
        if not self.require_user(user, "admin"):
            return
        form = self.read_form()
        post_id = form.get("post_id", "")
        with db_connect() as db:
            db.execute("DELETE FROM likes WHERE post_id = ?", (post_id,))
            db.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
            db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
            db.commit()
        self.redirect("/admin")


    # -- new detail pages -----------------------------------------------

    def admin_post_detail_page(self, user, query):
        """Mirrors A_View_Post_Details.jsp — admin sees full detail of one post."""
        if not self.require_user(user, "admin"):
            return
        post_id = query.get("id", [""])[0]
        post = query_one("SELECT * FROM posts WHERE id = ?", (post_id,))
        if not post:
            return self.send_html("Admin", "<section class='panel'><p>Post not found.</p><a href='/admin'>&laquo; Back</a></section>", user=user)

        file_block = "<p class='muted'>No file attached.</p>"
        if post["filename"]:
            file_url = f"/uploads/{quote(post['filename'])}"
            image_types = (".png", ".jpg", ".jpeg", ".gif", ".webp")
            if post["filename"].lower().endswith(image_types):
                file_block = f"<img class='avatar-large' src='{file_url}' alt='Post image'>"
            else:
                file_block = f"<a href='{file_url}'>Download: {clean(post['filename'])}</a>"

        score = misinformation_score(post["description"])
        review = "Needs review" if score else "Normal"

        comments = query_all(
            "SELECT * FROM comments WHERE post_id = ? ORDER BY created_at", (post_id,)
        )
        comment_rows = "".join(
            f"<tr><td>{clean(c['username'])}</td><td>{clean(c['comment'])}</td><td>{clean(c['created_at'])}</td></tr>"
            for c in comments
        ) or "<tr><td colspan='3'>No comments yet.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>Post Details</h2>
            <div class="profile-card">
                {file_block}
                <table>
                    <tr><th>Post ID</th><td>{clean(str(post['id']))}</td></tr>
                    <tr><th>Posted By</th><td>{clean(post['sender'])}</td></tr>
                    <tr><th>Title / Topic</th><td>{clean(post['title'])}</td></tr>
                    <tr><th>Category / Use</th><td>{clean(post['category']) or 'General'}</td></tr>
                    <tr><th>Description</th><td>{clean(post['description'])}</td></tr>
                    <tr><th>Filename</th><td>{clean(post['filename']) or 'None'}</td></tr>
                    <tr><th>Posted Date</th><td>{clean(post['created_at'])}</td></tr>
                    <tr><th>Review Status</th><td>{review}</td></tr>
                </table>
            </div>
            <h3>Comments on this post</h3>
            <table>
                <tr><th>Commenter</th><th>Comment</th><th>Date</th></tr>
                {comment_rows}
            </table>
            <p style="margin-top:1rem">
                <form method="post" action="/admin/post/delete" style="display:inline"
                      onsubmit="return confirm('Remove this post?');">
                    <input type="hidden" name="post_id" value="{post['id']}">
                    <button class="danger">Remove Post</button>
                </form>
                &nbsp; <a href="/admin">&laquo; Back to Admin Dashboard</a>
            </p>
        </section>
        """
        self.send_html("Post Details", body, user=user)

    def user_post_detail_page(self, user, query):
        """Mirrors U_View_Post_Details.jsp — user sees full detail of their own post."""
        if not self.require_user(user):
            return
        post_id = query.get("id", [""])[0]
        post = query_one(
            "SELECT * FROM posts WHERE id = ? AND sender = ?",
            (post_id, user["username"]),
        )
        if not post:
            return self.send_html("My Posts", "<section class='panel'><p>Post not found or not yours.</p><a href='/posts'>&laquo; Back</a></section>", user=user)

        file_block = "<p class='muted'>No file attached.</p>"
        if post["filename"]:
            file_url = f"/uploads/{quote(post['filename'])}"
            image_types = (".png", ".jpg", ".jpeg", ".gif", ".webp")
            if post["filename"].lower().endswith(image_types):
                file_block = f"<img class='avatar-large' src='{file_url}' alt='Post image'>"
            else:
                file_block = f"<a href='{file_url}'>Download: {clean(post['filename'])}</a>"

        comments = query_all(
            "SELECT * FROM comments WHERE post_id = ? ORDER BY created_at", (post_id,)
        )
        comment_rows = "".join(
            f"<tr><td>{clean(c['username'])}</td><td>{clean(c['comment'])}</td><td>{clean(c['created_at'])}</td></tr>"
            for c in comments
        ) or "<tr><td colspan='3'>No comments yet.</td></tr>"

        body = f"""
        <section class="panel">
            <h2>Post Details</h2>
            <div class="profile-card">
                {file_block}
                <table>
                    <tr><th>Post ID</th><td>{clean(str(post['id']))}</td></tr>
                    <tr><th>Your Username</th><td>{clean(post['sender'])}</td></tr>
                    <tr><th>Post Title / Topic</th><td>{clean(post['title'])}</td></tr>
                    <tr><th>Category / Use</th><td>{clean(post['category']) or 'General'}</td></tr>
                    <tr><th>Description</th><td>{clean(post['description'])}</td></tr>
                    <tr><th>Filename</th><td>{clean(post['filename']) or 'None'}</td></tr>
                    <tr><th>Posted Date</th><td>{clean(post['created_at'])}</td></tr>
                </table>
            </div>
            <h3>Comments</h3>
            <table>
                <tr><th>Commenter</th><th>Comment</th><th>Date</th></tr>
                {comment_rows}
            </table>
            <p style="margin-top:1rem"><a href="/posts">&laquo; Back to My Posts</a></p>
        </section>
        """
        self.send_html("Post Details", body, user=user)

    def log_message(self, format, *args):
        # Suppress per-request console noise; errors still show via log_error
        pass


def main():
    setup_database()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), MisinfoHandler)
    print(f"Server running at http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()