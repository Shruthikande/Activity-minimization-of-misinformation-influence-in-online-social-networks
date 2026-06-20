# Misinformation Influence Minimization in Online Social Networks

A simple social networking web application built with **Python, Flask, and SQLite**
that automatically detects and blocks misinformation.

## What This Project Does

- Users can **register** (admin must approve before login works) and **login**
- Users can **send and accept friend requests**
- Users can **create posts**, **like posts**, and **comment** on posts
- Users can **chat** privately with their friends
- Admin can maintain a list of **filter words** (e.g. fake, hoax, scam)
- If a user's post or comment contains a filter word, it is **automatically
  flagged** and that user's account is **automatically blocked**
- Admin has a dashboard to **approve users**, **manage filter words**,
  **view flagged content**, and **block/delete users**

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite (no separate database server needed!)
- **Frontend:** HTML, Bootstrap 5, Jinja2 templates

## How to Run This Project

### 1. Install requirements
```
pip install -r requirements.txt --break-system-packages
```
(sqlite3 comes built into Python — nothing extra to install for the database!)

### 2. Run the app
```
python app.py
```
The very first time you run it, a file called `misinfo.db` is created
automatically and all tables are set up for you (using `schema.sql`).

Open your browser at `http://127.0.0.1:5000`

### Default Admin Login
```
Username: admin
Password: admin123
```

## How the Misinformation Detection Works

This project uses a simple **keyword-matching** approach to demonstrate
misinformation detection:

1. Admin adds words to the `filter_words` table (e.g. "fake", "hoax")
2. Whenever a user creates a post or writes a comment, the text is
   checked against this filter word list (case-insensitive)
3. If a match is found, the post/comment is marked `flagged = 1`
   and the user's account is automatically blocked
4. Admin can review all flagged content from the Admin Panel

## Project Structure
```
misinfo_flask/
├── app.py              -> Main Flask application (all routes/logic)
├── schema.sql           -> Database schema (runs automatically on first start)
├── requirements.txt     -> Python dependencies
├── misinfo.db            -> Created automatically when you first run app.py
├── templates/           -> All HTML pages (Jinja2 templates)
│   ├── base.html
│   ├── index.html
│   ├── login.html / register.html
│   ├── dashboard.html / friends.html
│   ├── create_post.html / feed.html / post_detail.html
│   ├── chat.html
│   └── admin_login.html / admin_dashboard.html / admin_users.html
│       / admin_filters.html / admin_misinformation.html
└── README.md
├── misinfo.db            -> Auto-created on first run (not in repo)
```

## Author
Shruthi Kande