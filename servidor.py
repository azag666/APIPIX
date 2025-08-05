# -*- coding: utf-8 -*-
# Importa as bibliotecas necessárias
import sqlite3
import requests
import uuid
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from datetime import datetime
import functools
import os

# Inicializa a aplicação Flask
app = Flask(__name__)
# Habilita o CORS para permitir requisições de diferentes origens, como o seu frontend.
CORS(app)

# Nome do arquivo do banco de dados SQLite
DATABASE = 'apis.db'

# --- Funções para gerenciar o banco de dados ---
def get_db():
    """
    Função para obter a conexão com o banco de dados.
    A conexão é armazenada no contexto de requisição 'g' para ser reutilizada.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # Configura o retorno para ser um dicionário (acesso por nome da coluna)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """
    Fecha a conexão com o banco de dados no final da requisição.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """
    Inicializa o banco de dados, criando as tabelas se elas não existirem.
    Isso deve ser chamado uma vez na inicialização da aplicação.
    """
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Tabela de usuários para autenticação
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                auth_token TEXT NOT NULL UNIQUE
            )
        """)
        # Tabela de APIs com foreign key para o usuário
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                public_key TEXT,
                secret_key TEXT,
                token TEXT,
                is_active INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        db.commit()

# --- Funções de Autenticação e Utilitários ---
def get_user_id_from_token(token):
    """
    Busca o ID do usuário no banco de dados a partir do token de autenticação.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE auth_token = ?", (token,))
    user = cursor.fetchone()
    return user['id'] if user else None

def require_auth(func):
    """
    Decorador para proteger rotas.
    Verifica se a requisição possui um token de autenticação válido.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"message": "Token de autenticação ausente ou inválido."}), 401
        
        auth_token = auth_header.split(' ')[1]
        user_id = get_user_id_from_token(auth_token)
        
        if not user_id:
            return jsonify({"message": "Token de autenticação inválido."}), 401
        
        kwargs['user_id'] = user_id
        return func(*args, **kwargs)
    return wrapper

# --- Rotas de Usuário ---
@app.route('/users/register', methods=['POST'])
def register_user():
    """
    Rota para registrar um novo usuário e gerar um token de autenticação.
    """
    db = get_db()
    cursor = db.cursor()
    username = request.json.get('username')
    
    if not username:
        return jsonify({"message": "Username é obrigatório."}), 400
    
    try:
        auth_token = str(uuid.uuid4())
        cursor.execute("INSERT INTO users (username, auth_token) VALUES (?, ?)", (username, auth_token))
        db.commit()
        return jsonify({"message": "Usuário registrado com sucesso!", "username": username, "auth_token": auth_token}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username já existe."}), 400

# --- Rotas de Gerenciamento de APIs ---
@app.route('/apis', methods=['GET', 'POST'])
@require_auth
def manage_apis(user_id):
    """
    Rota para adicionar uma nova API ou listar as APIs de um usuário.
    """
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        data = request.json
        name = data.get('name')
        api_type = data.get('type')
        public_key = data.get('publicKey', '')
        secret_key = data.get('secretKey', '')
        token = data.get('token', '')

        try:
            cursor.execute("""
                INSERT INTO apis (user_id, name, type, public_key, secret_key, token)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, name, api_type, public_key, secret_key, token))
            db.commit()
            return jsonify({"message": "API salva com sucesso!"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"message": "Já existe uma API com este nome para este usuário."}), 400

    if request.method == 'GET':
        cursor.execute("SELECT id, name, is_active FROM apis WHERE user_id = ?", (user_id,))
        apis = [{"id": row['id'], "name": row['name'], "isActive": bool(row['is_active'])} for row in cursor.fetchall()]
        return jsonify(apis)

@app.route('/apis/set-active/<int:api_id>', methods=['POST'])
@require_auth
def set_active_api(user_id, api_id):
    """
    Rota para definir qual API de um usuário está ativa.
    """
    db = get_db()
    cursor = db.cursor()

    # Desativa todas as APIs do usuário
    cursor.execute("UPDATE apis SET is_active = 0 WHERE user_id = ?", (user_id,))
    
    # Ativa a API selecionada para o usuário
    cursor.execute("UPDATE apis SET is_active = 1 WHERE id = ? AND user_id = ?", (api_id, user_id))
    db.commit()
    
    if cursor.rowcount == 0:
        return jsonify({"message": "API não encontrada ou não pertence ao usuário."}), 404

    return jsonify({"message": f"API com ID {api_id} ativada."}), 200

# --- Rotas para Geração e Consulta de Pix ---
@app.route('/gerar-pix', methods=['POST'])
@require_auth
def gerar_pix(user_id):
    """
    Rota para gerar um Pix usando a API ativa do usuário.
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT name, type, public_key, secret_key, token FROM apis WHERE user_id = ? AND is_active = 1", (user_id,))
    active_api = cursor.fetchone()

    if not active_api:
        return jsonify({"message": "Nenhuma API de pagamento ativa. Ative uma no seu painel de controle."}), 400

    name, api_type, public_key, secret_key, token = active_api
    data = request.json
    amount = data.get('amount')

    # Lógica para chamar a API de pagamento correta
    if api_type == 'oasyfy':
        headers = {
            'Content-Type': 'application/json',
            'x-public-key': public_key,
            'x-secret-key': secret_key
        }
        body = {
            "identifier": f"checkout-{datetime.now().strftime('%Y%m%d%H%M%S')}-{user_id}",
            "amount": amount,
            "client": {
                "name": "Cliente Checkout",
                "email": f"checkout-{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
                "phone": "00000000000",
                "document": "12345678900" 
            },
            "products": [{"id": "1", "name": "Produto", "quantity": 1, "price": amount }],
            "callbackUrl": "https://seu_webhook_de_confirmacoes"
        }
        try:
            response = requests.post('https://app.oasyfy.com/api/v1/gateway/pix/receive', headers=headers, json=body)
            response.raise_for_status() 
            response_data = response.json()
            return jsonify({
                "pix_code": response_data.get('pix', {}).get('code'),
                "transaction_id": response_data.get('id')
            })
        except requests.exceptions.RequestException as e:
            return jsonify({"message": f"Erro na requisição Oasyfy: {str(e)}"}), 500

    elif api_type == 'pushinpay':
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token
        }
        body = {
            "name": "Cliente Checkout",
            "email": f"checkout-{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
            "cpf": "12345678901",
            "phone": "16977777777",
            "paymentMethod": "PIX",
            "amount": amount * 100,
            "traceable": True,
            "items": [
                {
                    "unitPrice": amount * 100,
                    "title": "Compra de Produto",
                    "quantity": 1,
                    "tangible": False
                }
            ],
            "postbackUrl": "https://seu_webhook_de_confirmacoes"
        }
        try:
            response = requests.post('https://api.pushinpay.com.br/api/v1/pix/cashin', headers=headers, json=body)
            response.raise_for_status()
            response_data = response.json()
            return jsonify({
                "pix_code": response_data.get('qr_code'),
                "transaction_id": response_data.get('id')
            })
        except requests.exceptions.RequestException as e:
            return jsonify({"message": f"Erro na requisição Pushinpay: {str(e)}"}), 500
    
    elif api_type == 'ghostpay':
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token
        }
        body = {
            "name": "Cliente Checkout",
            "email": f"checkout-{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
            "cpf": "12345678901",
            "phone": "+5516999999999",
            "paymentMethod": "PIX",
            "amount": amount * 100,
            "traceable": True,
            "items": [
                {
                    "unitPrice": amount * 100,
                    "title": "Acesso a Curso Online",
                    "quantity": 1,
                    "tangible": False
                }
            ],
            "postbackUrl": "https://seu_webhook_de_confirmacoes"
        }
        try:
            response = requests.post('https://example.com.br/api/v1/transaction.purchase', headers=headers, json=body)
            response.raise_for_status()
            response_data = response.json()
            return jsonify({
                "pix_code": response_data.get('pixCode'),
                "transaction_id": response_data.get('id')
            })
        except requests.exceptions.RequestException as e:
            return jsonify({"message": f"Erro na requisição Ghostpay: {str(e)}"}), 500

    return jsonify({"message": f"API '{api_type}' não suportada."}), 400


@app.route('/verificar-pix', methods=['GET'])
@require_auth
def verificar_pix(user_id):
    """
    Rota para verificar o status de um Pix usando a API ativa do usuário.
    """
    db = get_db()
    cursor = db.cursor()
    transaction_id = request.args.get('transaction_id')

    if not transaction_id:
        return jsonify({"message": "ID da transação é obrigatório."}), 400

    cursor.execute("SELECT name, type, public_key, secret_key, token FROM apis WHERE user_id = ? AND is_active = 1", (user_id,))
    active_api = cursor.fetchone()

    if not active_api:
        return jsonify({"message": "Nenhuma API de pagamento ativa. Ative uma no seu painel de controle."}), 400
    
    name, api_type, public_key, secret_key, token = active_api

    # Lógica para chamar o endpoint de consulta correto para cada API
    if api_type == 'oasyfy':
        headers = {
            'x-public-key': public_key,
            'x-secret-key': secret_key
        }
        try:
            # A documentação da Oasyfy para GET é diferente
            response = requests.get(f'https://app.oasyfy.com/api/v1/gateway/payments/{transaction_id}', headers=headers)
            response.raise_for_status()
            return jsonify({"status": response.json().get('status')})
        except requests.exceptions.RequestException as e:
            return jsonify({"message": f"Erro na requisição Oasyfy: {str(e)}"}), 500
    
    elif api_type == 'pushinpay' or api_type == 'ghostpay':
        headers = {
            'Authorization': token
        }
        try:
            # Documentação da Ghostpay/Pushinpay para GET /transaction.getPayment
            response = requests.get(f'https://example.com.br/api/v1/transaction.getPayment?id={transaction_id}', headers=headers)
            response.raise_for_status()
            return jsonify({"status": response.json().get('status')})
        except requests.exceptions.RequestException as e:
            return jsonify({"message": f"Erro na requisição {api_type}: {str(e)}"}), 500

    return jsonify({"message": f"API '{api_type}' não suportada para consulta."}), 400


# Inicializa o banco de dados antes de iniciar o servidor
# No Vercel, isso será executado pelo vercel-build.sh
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
