from flask import Flask, request, jsonify
import subprocess
import sqlite3

app = Flask(__name__)

DB_PATH = "data/users.db"

@app.route("/ping")
def ping():
    # Vulnerabilidad: interpolación directa en comando -> command injection posible
    host = request.args.get("host", "")
    # aquí usamos subprocess.getoutput con una cadena (shell implicit)
    output = subprocess.getoutput(f"ping -c 1 {host}")
    return "<pre>" + output + "</pre>"

@app.route("/user")
def user():
    # Vulnerabilidad: concatenación de la consulta SQL => SQL injection posible
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT id, username, fullname FROM users WHERE username = '{username}';"
    try:
        c.execute(query)
        rows = c.fetchall()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "fullname": r[2]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
