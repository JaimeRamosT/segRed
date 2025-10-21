# vulnapp/app.py
from flask import Flask, request, jsonify
import subprocess
import sqlite3
from log_utils import get_logger, log_request, check_and_record_suspicious, record_sql_error, client_ip_from_request
from log_utils import IDS_STATE, client_ip_from_request
import time

app = Flask(__name__)
logger = get_logger("vulnapp", log_file="vulnapp.log")

DB_PATH = "data/users.db"

@app.before_request
def before():
    ip = client_ip_from_request(request)
    blocked = False
    blocked_until = IDS_STATE["blocked"].get(ip)
    if blocked_until and time.time() < blocked_until:
        # Log de intento bloqueado
        log_request(logger, request, result="BLOCKED")
        return jsonify({"error": "IP temporalmente bloqueada"}), 429

@app.route("/ping")
def ping():
    ip = client_ip_from_request(request)
    # registrar petición
    log_request(logger, request)

    host = request.args.get("host", "")
    # NOTA: esta app es vulnerable; usamos getoutput para demostrar command injection
    try:
        output = subprocess.getoutput(f"ping -c 1 {host}")
        log_request(logger, request, result="PING_OK")
        return "<pre>" + output + "</pre>"
    except Exception as e:
        logger.exception("Ping error")
        log_request(logger, request, result="PING_ERROR", extra=str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/user")
def user():
    ip = client_ip_from_request(request)

    # Comprobar parámetros sospechosos e IDS
    suspicious, reason = check_and_record_suspicious(logger, request)
    if suspicious:
        log_request(logger, request, result="SUSPICIOUS", extra=reason)
        # Si es bloqueo explícito, devolvemos 429
        if reason.startswith("blocked"):
            return jsonify({"error": "IP temporalmente bloqueada"}), 429
        # Si solo es sospechoso, podemos continuar pero lo registramos (a elección)
        # Aquí decidimos continuar para observar la vulnerabilidad, pero ya quedó logueada.
    
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT id, username, fullname FROM users WHERE username = '{username}';"
    try:
        c.execute(query)
        rows = c.fetchall()
    except Exception as e:
        # Registrar detalle del error SQL para detección de escaneo
        record_sql_error(logger, ip, query_snippet=query[:200], error_str=str(e))
        conn.close()
        log_request(logger, request, result="SQL_ERROR", extra=str(e))
        return jsonify({"error": str(e)}), 500

    conn.close()
    log_request(logger, request, result="SQL_OK", extra=f"rows={len(rows)}")
    return jsonify([{"id": r[0], "username": r[1], "fullname": r[2]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
