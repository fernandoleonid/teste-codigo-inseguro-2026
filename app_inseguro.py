from flask import Flask, request, jsonify
from werkzeug.serving import WSGIRequestHandler
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import sqlite3

app = Flask(__name__)

# Use environment variable when available; fallback is generated at startup.
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY") or secrets.token_urlsafe(32)

DB_PATH = "database.db"


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Avoid leaking framework/version details via the Server response header.
    response.headers["Server"] = "Server"
    return response


@app.route("/")
def index():
    return """
    <h1>Aplicacao Segura para Testes</h1>
    <p>Versao com melhorias de seguranca para fins educacionais.</p>
    <h2>Endpoints disponiveis:</h2>
    <ul>
        <li><a href="/login">Login (POST)</a></li>
        <li><a href="/api/user/1">API User (ID=1)</a></li>
    </ul>
    """


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY,
                     username TEXT UNIQUE,
                     password TEXT,
                     role TEXT)"""
    )

    admin_user = "admin"
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_password:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_user, generate_password_hash(admin_password), "administrator"),
        )

    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username e password sao obrigatorios"}), 400

    conn = get_db_connection()
    cursor = conn.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        return jsonify(
            {
                "status": "success",
                "message": f"Bem-vindo {user['username']}",
                "role": user["role"],
            }
        )

    return jsonify({"status": "error", "message": "Credenciais invalidas"}), 401


@app.route("/api/user/<int:user_id>")
def get_user(user_id: int):
    conn = get_db_connection()
    cursor = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        })

    return jsonify({"error": "Usuario nao encontrado"}), 404


if __name__ == "__main__":
    init_db()

    # Ensure Flask/Werkzeug does not leak server/version details.
    WSGIRequestHandler.server_version = "Server"
    WSGIRequestHandler.sys_version = ""

    app.run(host="127.0.0.1", port=5000, debug=False)
