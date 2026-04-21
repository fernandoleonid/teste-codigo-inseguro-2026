from flask import Flask, request, jsonify
import hashlib
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Aplicação Vulnerável para Testes</h1>
    <p>Esta aplicação contém vulnerabilidades intencionais para fins educacionais.</p>
    <h2>Endpoints disponíveis:</h2>
    <ul>
        <li><a href="/login">Login (POST)</a></li>
        <li><a href="/debug">Debug Info</a></li>
        <li><a href="/api/user/1">API User (ID=1)</a></li>
    </ul>
    '''

SECRET_KEY = "minha_senha_secreta_123"
API_TOKEN = "token_admin_2024"

def hash_password(password):

    return hashlib.md5(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect('database.db')
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, 
                     username TEXT, 
                     password TEXT,
                     role TEXT)''')
    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ('admin', hash_password('admin123'), 'administrator'))
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hash_password(password)}'"
    
    conn = get_db_connection()
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:

        return jsonify({
            'status': 'success',
            'message': f'Bem-vindo {user[1]}',
            'role': user[3],
            'api_token': API_TOKEN 
        })
    return jsonify({'status': 'error', 'message': 'Credenciais inválidas'}), 401

@app.route('/api/user/<user_id>')
def get_user(user_id):

    query = "SELECT * FROM users WHERE id=" + user_id
    conn = get_db_connection()
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'role': user[3]
        })
    return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/debug')
def debug_info():

    return jsonify({
        'secret_key': SECRET_KEY,
        'python_version': '3.9',
        'debug_mode': True
    })

if __name__ == '__main__':

    init_db()
    
    app.run(host='0.0.0.0', port=5000, debug=True)