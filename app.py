"""
PROJECT: Misinformation Influence Minimization in Online Social Networks
TECH USED: Python, Flask, MySQL

WHAT THIS PROJECT DOES (simple explanation):
1. Users can register and login (admin must approve new users first)
2. Users can send/accept friend requests
3. Users can create posts, like posts, and comment on posts
4. Users can chat with their friends
5. Admin can add "filter words" (like fake, hoax, scam)
6. If a user's post or comment contains a filter word, it is
   automatically marked as "flagged" and that user is blocked
7. Admin has a dashboard to approve users, manage filter words,
   view flagged content, and block/delete users
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import uuid
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "change_this_secret_key_in_production"   # needed for session/login to work

# ---------------------------------------------------------------------------
# Image upload settings (used by the "Create a Post" form)
# ---------------------------------------------------------------------------
UPLOAD_FOLDER = Path(__file__).parent / "static" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_image(filename):
    """True if the uploaded file's extension looks like a normal image."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def save_post_image(file_storage):
    """
    Saves an uploaded image to static/uploads with a random filename
    (so two people uploading 'photo.jpg' don't overwrite each other)
    and returns just the filename to store in the database.
    Returns '' if no valid file was uploaded.
    """
    if not file_storage or file_storage.filename == "":
        return ""
    if not allowed_image(file_storage.filename):
        return ""

    original_name = secure_filename(file_storage.filename)
    extension = original_name.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{extension}"
    file_storage.save(UPLOAD_FOLDER / unique_name)
    return unique_name


# ---------------------------------------------------------------------------
# STEP 1: Connect to SQLite database
# ---------------------------------------------------------------------------
# SQLite stores the whole database in a single file - no separate
# database server needed! The file is created automatically the
# first time you run this app.
DB_PATH = Path(__file__).parent / "misinfo.db"


def get_db():
    """Opens a new connection to the SQLite database file."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row   # lets us access columns by name, like row["username"]
    return db


def init_db():
    """Creates all tables (if they don't already exist) by running schema.sql."""
    schema_path = Path(__file__).parent / "schema.sql"
    db = get_db()
    with open(schema_path, "r") as f:
        db.executescript(f.read())
    db.commit()

    # ---- lightweight migration ----
    # if you already had a misinfo.db from before image uploads were added,
    # schema.sql's CREATE TABLE IF NOT EXISTS won't add the new column to
    # your existing table, so we add it here if it's missing.
    existing_columns = [row[1] for row in db.execute("PRAGMA table_info(posts)").fetchall()]
    if "image_filename" not in existing_columns:
        db.execute("ALTER TABLE posts ADD COLUMN image_filename TEXT DEFAULT ''")
        db.commit()

    db.close()


def run_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """
    A simple helper function so we don't have to repeat the same
    connect -> cursor -> execute -> close steps in every route.

    Example usage:
        run_query("SELECT * FROM users WHERE username=?", (username,), fetchone=True)
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(sql, params or ())

    result = None
    if fetchone:
        row = cursor.fetchone()
        result = dict(row) if row else None
    if fetchall:
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
    if commit:
        db.commit()
        result = cursor.lastrowid

    cursor.close()
    db.close()
    return result


# ---------------------------------------------------------------------------
# STEP 2: Misinformation filter logic (the "AI/automation" part of project)
# ---------------------------------------------------------------------------

def text_contains_filter_word(text):
    """
    Checks if the given text (a post or comment) contains any word
    from the admin's filter_words table. This is a simple keyword
    matching approach - not real machine learning, but it demonstrates
    the same idea: automatically detecting misinformation.
    """
    filter_words = run_query("SELECT word FROM filter_words", fetchall=True)
    text_lower = text.lower()

    for row in filter_words:
        if row["word"].lower() in text_lower:
            return True   # found a bad word -> this text is flagged
    return False


def block_user(username):
    """When a user posts misinformation, their account gets auto-blocked."""
    run_query("UPDATE users SET blocked = 1 WHERE username = ?", (username,), commit=True)


# ---------------------------------------------------------------------------
# STEP 3: Helper functions to check who is logged in
# ---------------------------------------------------------------------------

def get_logged_in_user():
    return session.get("user")


def admin_is_logged_in():
    return session.get("is_admin", False)


# ---------------------------------------------------------------------------
# STEP 4: PUBLIC PAGES (no login required)
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template(
        "index.html",
        user=get_logged_in_user(),
        is_admin=admin_is_logged_in()
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form.get("email", "")
        mobile = request.form.get("mobile", "")

        # check if username is already taken
        existing_user = run_query("SELECT id FROM users WHERE username = ?", (username,), fetchone=True)
        if existing_user:
            flash("That username is already taken. Please choose another.")
            return redirect(url_for("register"))

        # save new user with status = 'pending' (admin must approve before login works)
        run_query(
            "INSERT INTO users (username, password, email, mobile, status) VALUES (?, ?, ?, ?, 'pending')",
            (username, password, email, mobile),
            commit=True
        )
        flash("Registration successful! Please wait for admin approval before logging in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = run_query(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
            fetchone=True
        )

        if not user:
            flash("Invalid username or password.")
        elif user["status"] != "approved":
            flash("Your account is still waiting for admin approval.")
        elif user["blocked"]:
            flash("Your account has been blocked by admin for posting misinformation.")
        else:
            # login successful - save username in session
            session["user"] = username
            session["is_admin"] = False
            return redirect(url_for("dashboard"))

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()   # removes the logged-in user from session
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# STEP 5: USER PAGES (must be logged in to access)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    post_count = run_query("SELECT COUNT(*) AS total FROM posts WHERE sender = ?", (user,), fetchone=True)["total"]

    friend_count = run_query(
        "SELECT COUNT(*) AS total FROM friend_requests WHERE status='Accepted' AND (request_from=? OR request_to=?)",
        (user, user), fetchone=True
    )["total"]

    return render_template("dashboard.html", user=user, post_count=post_count, friend_count=friend_count)


@app.route("/friends", methods=["GET", "POST"])
def friends():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    # sending a new friend request
    if request.method == "POST":
        to_user = request.form["to_user"].strip()

        if to_user == user:
            flash("You can't send a friend request to yourself.")
            return redirect(url_for("friends"))

        target = run_query("SELECT id FROM users WHERE username=?", (to_user,), fetchone=True)
        if not target:
            flash(f"No user named '{to_user}' was found.")
            return redirect(url_for("friends"))

        # has a request already gone between these two people, in EITHER
        # direction? this stops: duplicate pending requests, re-sending a
        # request after the other person already accepted, and re-sending
        # right back to someone who already sent one to you.
        existing = run_query(
            """SELECT * FROM friend_requests
               WHERE (request_from=? AND request_to=?) OR (request_from=? AND request_to=?)""",
            (user, to_user, to_user, user), fetchone=True
        )

        if existing:
            if existing["status"] == "Accepted":
                flash(f"You and {to_user} are already friends.")
            else:
                flash(f"There's already a pending friend request between you and {to_user}.")
            return redirect(url_for("friends"))

        run_query(
            "INSERT INTO friend_requests (request_from, request_to, status) VALUES (?, ?, 'Pending')",
            (user, to_user), commit=True
        )
        flash(f"Friend request sent to {to_user}")
        return redirect(url_for("friends"))

    # friend requests sent to me that I haven't accepted yet
    incoming_requests = run_query(
        "SELECT * FROM friend_requests WHERE request_to=? AND status='Pending'",
        (user,), fetchall=True
    )

    # people I am already friends with
    accepted = run_query(
        "SELECT request_from, request_to FROM friend_requests WHERE status='Accepted' AND (request_from=? OR request_to=?)",
        (user, user), fetchall=True
    )
    my_friends = [row["request_to"] if row["request_from"] == user else row["request_from"] for row in accepted]

    # usernames already involved in ANY pending/accepted request with me,
    # so search results don't show people you can't currently add anyway
    related = run_query(
        "SELECT request_from, request_to FROM friend_requests WHERE request_from=? OR request_to=?",
        (user, user), fetchall=True
    )
    already_related = {user}
    for row in related:
        already_related.add(row["request_from"])
        already_related.add(row["request_to"])

    # search box: only runs a query if the person actually typed something
    search_query = request.args.get("q", "").strip()
    search_results = []
    if search_query:
        candidates = run_query(
            """SELECT username FROM users
               WHERE username LIKE ? AND status='approved' AND blocked=0""",
            (f"%{search_query}%",), fetchall=True
        )
        search_results = [c for c in candidates if c["username"] not in already_related]

    return render_template(
        "friends.html", user=user, incoming=incoming_requests, friends=my_friends,
        search_query=search_query, search_results=search_results
    )


@app.route("/friends/accept/<int:request_id>")
def accept_friend(request_id):
    if not get_logged_in_user():
        return redirect(url_for("login"))

    run_query("UPDATE friend_requests SET status='Accepted' WHERE id=?", (request_id,), commit=True)
    flash("Friend request accepted!")
    return redirect(url_for("friends"))


@app.route("/friends/reject/<int:request_id>")
def reject_friend(request_id):
    if not get_logged_in_user():
        return redirect(url_for("login"))

    # we delete the row rather than just marking it "Rejected" so the same
    # two people can send a fresh friend request again later if they want
    run_query("DELETE FROM friend_requests WHERE id=?", (request_id,), commit=True)
    flash("Friend request rejected.")
    return redirect(url_for("friends"))


@app.route("/posts", methods=["GET", "POST"])
def posts():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        category = request.form.get("category", "")
        image_filename = save_post_image(request.files.get("image"))

        # check the post against the misinformation filter words
        is_flagged = text_contains_filter_word(title) or text_contains_filter_word(description)

        run_query(
            "INSERT INTO posts (sender, title, description, category, image_filename, flagged) VALUES (?, ?, ?, ?, ?, ?)",
            (user, title, description, category, image_filename, is_flagged), commit=True
        )

        if is_flagged:
            block_user(user)
            flash("This post contains flagged misinformation words. Your account has been blocked.")
            session.clear()
            return redirect(url_for("login"))

        flash("Post created successfully!")
        return redirect(url_for("feed"))

    return render_template("create_post.html", user=user)


@app.route("/feed")
def feed():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    all_posts = run_query(
        """SELECT posts.*,
                  (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS likes_count,
                  (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.flagged = 0) AS comments_count
           FROM posts
           WHERE flagged = 0
           ORDER BY created_at DESC""",
        fetchall=True
    )
    return render_template("feed.html", user=user, posts=all_posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post_detail(post_id):
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    # adding a new comment
    if request.method == "POST":
        comment_text = request.form["comment"]
        is_flagged = text_contains_filter_word(comment_text)

        run_query(
            "INSERT INTO comments (post_id, username, comment, flagged) VALUES (?, ?, ?, ?)",
            (post_id, user, comment_text, is_flagged), commit=True
        )

        if is_flagged:
            block_user(user)
            flash("Your comment contained flagged misinformation words. Your account has been blocked.")
            session.clear()
            return redirect(url_for("login"))

        return redirect(url_for("post_detail", post_id=post_id))

    post = run_query("SELECT * FROM posts WHERE id=?", (post_id,), fetchone=True)

    comments = run_query(
        "SELECT * FROM comments WHERE post_id=? AND flagged=0 ORDER BY created_at",
        (post_id,), fetchall=True
    )

    likes_count = run_query("SELECT COUNT(*) AS total FROM likes WHERE post_id=?", (post_id,), fetchone=True)["total"]

    already_liked = run_query(
        "SELECT id FROM likes WHERE post_id=? AND username=?", (post_id, user), fetchone=True
    )

    return render_template(
        "post_detail.html", user=user, post=post, comments=comments,
        likes_count=likes_count, already_liked=bool(already_liked)
    )


@app.route("/post/<int:post_id>/like")
def like_post(post_id):
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    existing_like = run_query(
        "SELECT id FROM likes WHERE post_id=? AND username=?", (post_id, user), fetchone=True
    )

    if existing_like:
        # already liked -> clicking again removes the like (unlike)
        run_query("DELETE FROM likes WHERE id=?", (existing_like["id"],), commit=True)
    else:
        run_query("INSERT INTO likes (post_id, username) VALUES (?, ?)", (post_id, user), commit=True)

    return redirect(url_for("post_detail", post_id=post_id))


@app.route("/chat/<friend>", methods=["GET", "POST"])
def chat(friend):
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        message_text = request.form["message"]
        run_query(
            "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
            (user, friend, message_text), commit=True
        )
        return redirect(url_for("chat", friend=friend))

    chat_messages = run_query(
        """SELECT * FROM messages
           WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
           ORDER BY created_at""",
        (user, friend, friend, user), fetchall=True
    )

    return render_template("chat.html", user=user, friend=friend, messages=chat_messages)


# ---------------------------------------------------------------------------
# STEP 6: ADMIN PAGES (must be logged in as admin)
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        admin = run_query(
            "SELECT * FROM admin WHERE username=? AND password=?", (username, password), fetchone=True
        )

        if admin:
            session["user"] = username
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin username or password.")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    pending_count = run_query("SELECT COUNT(*) AS total FROM users WHERE status='pending'", fetchone=True)["total"]
    flagged_posts = run_query("SELECT COUNT(*) AS total FROM posts WHERE flagged=1", fetchone=True)["total"]
    blocked_users = run_query("SELECT COUNT(*) AS total FROM users WHERE blocked=1", fetchone=True)["total"]
    total_users = run_query("SELECT COUNT(*) AS total FROM users", fetchone=True)["total"]

    return render_template(
        "admin_dashboard.html", pending_count=pending_count, flagged_posts=flagged_posts,
        blocked_users=blocked_users, total_users=total_users
    )


@app.route("/admin/users")
def admin_users():
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    all_users = run_query("SELECT * FROM users ORDER BY created_at DESC", fetchall=True)
    return render_template("admin_users.html", users=all_users)


@app.route("/admin/users/<username>/approve")
def approve_user(username):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    run_query("UPDATE users SET status='approved' WHERE username=?", (username,), commit=True)
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>/block")
def toggle_block_user(username):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    user = run_query("SELECT blocked FROM users WHERE username=?", (username,), fetchone=True)
    new_blocked_value = 0 if user["blocked"] else 1
    run_query("UPDATE users SET blocked=? WHERE username=?", (new_blocked_value, username), commit=True)
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>/delete")
def delete_user(username):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    run_query("DELETE FROM users WHERE username=?", (username,), commit=True)
    return redirect(url_for("admin_users"))


@app.route("/admin/filters", methods=["GET", "POST"])
def admin_filters():
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        word = request.form["word"]
        category = request.form.get("category", "Misinformation")
        run_query("INSERT INTO filter_words (word, category) VALUES (?, ?)", (word, category), commit=True)
        flash(f"Added '{word}' to the filter word list.")
        return redirect(url_for("admin_filters"))

    all_filter_words = run_query("SELECT * FROM filter_words ORDER BY id DESC", fetchall=True)
    return render_template("admin_filters.html", words=all_filter_words)


@app.route("/admin/filters/<int:word_id>/delete")
def delete_filter_word(word_id):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    run_query("DELETE FROM filter_words WHERE id=?", (word_id,), commit=True)
    return redirect(url_for("admin_filters"))


@app.route("/admin/flagged")
def admin_flagged():
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    flagged_posts = run_query("SELECT * FROM posts WHERE flagged=1 ORDER BY created_at DESC", fetchall=True)
    flagged_comments = run_query("SELECT * FROM comments WHERE flagged=1 ORDER BY created_at DESC", fetchall=True)

    return render_template("admin_misinformation.html", posts=flagged_posts, comments=flagged_comments)


@app.route("/admin/posts")
def admin_all_posts():
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    # every post, newest first, regardless of whether the filter flagged it
    all_posts = run_query(
        """SELECT posts.*, users.blocked AS sender_blocked
           FROM posts
           LEFT JOIN users ON users.username = posts.sender
           ORDER BY posts.created_at DESC""",
        fetchall=True
    )

    # every comment, newest first, regardless of whether the filter flagged it
    all_comments = run_query(
        """SELECT comments.*, users.blocked AS author_blocked, posts.title AS post_title
           FROM comments
           LEFT JOIN users ON users.username = comments.username
           LEFT JOIN posts ON posts.id = comments.post_id
           ORDER BY comments.created_at DESC""",
        fetchall=True
    )

    return render_template("admin_all_posts.html", posts=all_posts, comments=all_comments)


@app.route("/admin/posts/<int:post_id>/delete")
def delete_post(post_id):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    run_query("DELETE FROM posts WHERE id=?", (post_id,), commit=True)
    flash("Post deleted.")
    # send admin back to wherever they came from (All Posts or Flagged Content)
    return redirect(request.referrer or url_for("admin_all_posts"))


@app.route("/admin/posts/<int:post_id>/block-author")
def block_post_author(post_id):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    post = run_query("SELECT sender FROM posts WHERE id=?", (post_id,), fetchone=True)
    if post:
        run_query("UPDATE users SET blocked=1 WHERE username=?", (post["sender"],), commit=True)
        flash(f"{post['sender']} has been blocked.")

    return redirect(request.referrer or url_for("admin_all_posts"))


@app.route("/admin/comments/<int:comment_id>/delete")
def delete_comment(comment_id):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    run_query("DELETE FROM comments WHERE id=?", (comment_id,), commit=True)
    flash("Comment deleted.")
    return redirect(request.referrer or url_for("admin_all_posts"))


@app.route("/admin/comments/<int:comment_id>/block-author")
def block_comment_author(comment_id):
    if not admin_is_logged_in():
        return redirect(url_for("admin_login"))

    comment = run_query("SELECT username FROM comments WHERE id=?", (comment_id,), fetchone=True)
    if comment:
        run_query("UPDATE users SET blocked=1 WHERE username=?", (comment["username"],), commit=True)
        flash(f"{comment['username']} has been blocked.")

    return redirect(request.referrer or url_for("admin_all_posts"))


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# STEP 7: Run the Flask app
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()   # creates misinfo.db and all tables automatically if not already there
    app.run(debug=True)