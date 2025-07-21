import sqlite3
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from joblib import dump, load
import os
import schedule
import time
import threading
from datetime import datetime

DB_PATH = os.path.join("db", "logs.db")
MODEL_PATH = os.path.join("db", "model.joblib")

def train_model(verbose=True):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT decoded_input, verdict FROM logs WHERE verdict IN ('CLEAN', 'BLOCKED')")
    data = c.fetchall()
    conn.close()

    if not data:
        if verbose:
            print("⚠️ No data to train on.")
        return

    X_raw = [row[0] for row in data]
    y = [1 if row[1].startswith("BLOCKED") else 0 for row in data]

    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(X_raw)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    clf = LogisticRegression(max_iter=500)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    dump((clf, vectorizer), MODEL_PATH)
    if verbose:
        print(f"ML model retrained @ {datetime.now().strftime('%H:%M:%S')} | Samples: {len(X_raw)} | Accuracy: {acc*100:.2f}%")

def predict_input(text):
    if not os.path.exists(MODEL_PATH):
        return None, 0.0
    clf, vectorizer = load(MODEL_PATH)
    X = vectorizer.transform([text])
    proba = clf.predict_proba(X)[0][1]
    is_malicious = clf.predict(X)[0]
    return is_malicious, proba

def auto_train_loop():
    schedule.every(5).minutes.do(train_model)
    while True:
        schedule.run_pending()
        time.sleep(1)

# Starts in background thread
def start_training_daemon():
    thread = threading.Thread(target=auto_train_loop)
    thread.daemon = True
    thread.start()
