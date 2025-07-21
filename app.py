from flask import Flask, request, render_template
from middleware import SentinelWallMiddleware
from logger import init_db, log_input, is_duplicate_payload
from ml_engine import start_training_daemon, train_model,predict_input
from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO
import os
import sqlite3

train_model(verbose=True)         
start_training_daemon()           


app = Flask(__name__)
SentinelWallMiddleware(app)
init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/search')
def search():
    input_query = request.args.get('q', '')
    result_data = request.normalized_data.get('q', {})
    decoded = result_data.get("decoded", "")
    is_regex_malicious = result_data.get("malicious", False)
    verdict = "CLEAN"
    ip = request.remote_addr

    # ML check
    is_ml_malicious, confidence = predict_input(decoded)
    
    if is_regex_malicious or is_ml_malicious:
        verdict = "BLOCKED"
        if is_ml_malicious and not is_regex_malicious:
            verdict += " (ML)"

    log_input(input_query, decoded, verdict, ip)
    
    return render_template(
        'result.html',
        input=input_query,
        decoded=decoded,
        verdict=verdict,
        confidence=round(confidence * 100, 2)
    )

@app.route("/report")
def report():
    conn = sqlite3.connect("db/logs.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()

    total = len(logs)
    blocked = sum(1 for l in logs if "BLOCKED" in l[4])
    clean = total - blocked
    ip_counts = {}
    hash_counts = {}

    for l in logs:
        ip_counts[l[5]] = ip_counts.get(l[5], 0) + 1
        hash_counts[l[6]] = hash_counts.get(l[6], 0) + 1

    top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else "N/A"
    top_hash = max(hash_counts, key=hash_counts.get) if hash_counts else "N/A"

    return render_template("report.html", logs=logs, total=total, blocked=blocked, clean=clean, top_ip=top_ip, top_hash=top_hash)

@app.route("/report/pdf")
def report_pdf():
    conn = sqlite3.connect("db/logs.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()

    total = len(logs)
    blocked = sum(1 for l in logs if "BLOCKED" in l[4])
    clean = total - blocked
    ip_counts = {}
    hash_counts = {}

    for l in logs:
        ip_counts[l[5]] = ip_counts.get(l[5], 0) + 1
        hash_counts[l[6]] = hash_counts.get(l[6], 0) + 1

    top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else "N/A"
    top_hash = max(hash_counts, key=hash_counts.get) if hash_counts else "N/A"

    html = render_template("report.html", logs=logs, total=total, blocked=blocked, clean=clean, top_ip=top_ip, top_hash=top_hash)
    pdf = BytesIO()
    pisa.CreatePDF(BytesIO(html.encode("utf-8")), pdf)
    response = make_response(pdf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "inline; filename=threat-report.pdf"
    return response

@app.route('/logs')
def view_logs():
    import sqlite3
    conn = sqlite3.connect("db/logs.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
