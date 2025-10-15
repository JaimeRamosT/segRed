from flask import Flask, request, jsonify
import subprocess
import sqlite3
import re

app = Flask(__name__)

DB_PATH = "data/users.db"

# Validación estricta para hostname/IP simple: solo letras, números, dots, hyphens
HOST_RE = re.compile(r"^[A-Za-z0-9\.\-]+$")

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):
        return jsonify({"error": "host inválido"}), 400

    # Uso seguro: subprocess.run con lista de argumentos (no shell)
    try:
        proc = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
        output = proc.stdout + proc.stderr
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return "<pre>" + output + "</pre>"

@app.route("/user")
def user():
    username = request.args.get("username", "")
    # Validación básica: no separar comillas, longitud razonable
    if not username or len(username) > 100:
        return jsonify({"error": "username inválido"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Parameterized query para evitar SQL injection
    try:
        c.execute("SELECT id, username, fullname FROM users WHERE username = ?", (username,))
        rows = c.fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "fullname": r[2]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
