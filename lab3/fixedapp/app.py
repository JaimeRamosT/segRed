# fixedapp/app.py
from flask import Flask, request, jsonify
import subprocess
import sqlite3
import re
from log_utils import get_logger, log_request, check_and_record_suspicious, record_sql_error, client_ip_from_request

app = Flask(__name__)
logger = get_logger("fixedapp", log_file="fixedapp.log")

DB_PATH = "data/users.db"

HOST_RE = re.compile(r"^[A-Za-z0-9\.\-]+$")

@app.before_request
def before():
    ip = client_ip_from_request(request)
    from log_utils import IDS_STATE
    blocked_until = IDS_STATE["blocked"].get(ip)
    import time
    if blocked_until and time.time() < blocked_until:
        log_request(logger, request, result="BLOCKED")
        return jsonify({"error": "IP temporalmente bloqueada"}), 429

@app.route("/ping")
def ping():
    ip = client_ip_from_request(request)
    log_request(logger, request)

    host = request.args.get("host", "")
    suspicious, reason = check_and_record_suspicious(logger, request)
    if suspicious:
        log_request(logger, request, result="SUSPICIOUS", extra=reason)
        if reason.startswith("blocked"):
            return jsonify({"error": "IP temporalmente bloqueada"}), 429
        return jsonify({"error": "parámetro sospechoso detectado"}), 400

    if not HOST_RE.match(host):
        log_request(logger, request, result="VALIDATION_FAIL", extra="host invalid")
        return jsonify({"error": "host inválido"}), 400

    try:
        proc = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
        output = proc.stdout + proc.stderr
        log_request(logger, request, result="PING_OK")
        return "<pre>" + output + "</pre>"
    except Exception as e:
        logger.exception("Ping error")
        log_request(logger, request, result="PING_ERROR", extra=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/user")
def user():
    ip = client_ip_from_request(request)
    log_request(logger, request)

    suspicious, reason = check_and_record_suspicious(logger, request)
    if suspicious:
        log_request(logger, request, result="SUSPICIOUS", extra=reason)
        if reason.startswith("blocked"):
            return jsonify({"error": "IP temporalmente bloqueada"}), 429
        return jsonify({"error": "parámetro sospechoso detectado"}), 400

    username = request.args.get("username", "")
    if not username or len(username) > 100:
        log_request(logger, request, result="VALIDATION_FAIL", extra="username invalid")
        return jsonify({"error": "username inválido"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Parameterized query
        c.execute("SELECT id, username, fullname FROM users WHERE username = ?", (username,))
        rows = c.fetchall()
    except Exception as e:
        record_sql_error(logger, ip, query_snippet="SELECT ... WHERE username = ?", error_str=str(e))
        conn.close()
        log_request(logger, request, result="SQL_ERROR", extra=str(e))
        return jsonify({"error": str(e)}), 500

    conn.close()
    log_request(logger, request, result="SQL_OK", extra=f"rows={len(rows)}")
    return jsonify([{"id": r[0], "username": r[1], "fullname": r[2]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
