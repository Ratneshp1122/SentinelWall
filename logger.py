import sqlite3
from datetime import datetime
import os
import hashlib
DB_PATH = os.path.join("db", "logs.db")

def generate_payload_hash(decoded_input):
    return hashlib.sha256(decoded_input.encode('utf-8')).hexdigest()

def is_duplicate_payload(decoded_input):
    payload_hash = generate_payload_hash(decoded_input)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs WHERE payload_hash = ?", (payload_hash,))
    count = c.fetchone()[0]
    conn.close()
    return count > 0


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        raw_input TEXT,
        decoded_input TEXT,
        verdict TEXT,
        ip_address TEXT,
        payload_hash TEXT
    )''')
    conn.commit()
    conn.close()


def log_input(raw, decoded, verdict, ip):
    payload_hash = generate_payload_hash(decoded)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, raw_input, decoded_input, verdict, ip_address, payload_hash) VALUES (?, ?, ?, ?, ?, ?)", 
              (datetime.now().isoformat(), raw, decoded, verdict, ip, payload_hash))
    conn.commit()
    conn.close()
