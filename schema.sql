-- Misinformation Influence Minimization — SQLite Schema
-- This file runs automatically the first time you start app.py
-- (you do NOT need to run this manually, but it's here so you
-- can see and explain the database design in an interview)

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
    status TEXT NOT NULL DEFAULT 'pending',   -- pending / approved
    blocked INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_from TEXT NOT NULL,
    request_to TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',   -- Pending / Accepted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT DEFAULT '',
    image_filename TEXT DEFAULT '',
    flagged INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(post_id, username)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    comment TEXT NOT NULL,
    flagged INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS filter_words (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT NOT NULL,
    category TEXT DEFAULT 'Misinformation'
);

-- Default admin login: username = admin, password = admin123
INSERT OR IGNORE INTO admin (username, password) VALUES ('admin', 'admin123');

-- Some starter filter words (admin can add more from the Admin Panel)
INSERT OR IGNORE INTO filter_words (word, category) VALUES ('fake', 'Misinformation');
INSERT OR IGNORE INTO filter_words (word, category) VALUES ('hoax', 'Misinformation');
INSERT OR IGNORE INTO filter_words (word, category) VALUES ('scam', 'Misinformation');
INSERT OR IGNORE INTO filter_words (word, category) VALUES ('rumour', 'Misinformation');
INSERT OR IGNORE INTO filter_words (word, category) VALUES ('fraud', 'Misinformation');