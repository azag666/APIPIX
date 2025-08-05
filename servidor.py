# -*- coding: utf-8 -*-
# Importa as bibliotecas necessárias
import os
import psycopg2 # Importa o driver PostgreSQL
import uuid
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from datetime import datetime
import functools

# Inicializa a aplicação Flask
app = Flask(__name__)
# Habilita o CORS para permitir requisições de diferentes origens, como o seu frontend.
CORS(app)

# Nome da variável de ambiente que conterá a URL de conexão do Neon
DATABASE_URL = os.environ.get('DATABASE_URL')

# --- Funções para gerenciar o banco de dados ---
def get_db():
    """
    Função para obter a conexão com o banco de dados PostgreSQL.
    A conexão é armazenada no contexto de requisição 'g' para ser reutilizada.
    """
    if not hasattr(g, 'pg_db'):
        if not DATABASE_URL:
            raise ValueError("DATABASE_URL não configurada nas variáveis de ambiente.")
        g.pg_db = psycopg2.connect(DATABASE_URL)
        # Configura o cursor para retornar linhas como dicionários
        # Para acessar por nome da coluna: row['column_name']
        # Para acessar por índice: row[0]
        # psycopg2.extras.DictCursor pode ser usado para um comportamento mais parecido com sqlite3.Row
    return g.pg_db

@app.teardown_appcontext
def close_connection(exception):
    """
    Fecha a conexão com o banco de dados no final da requisição.
    """
    db = getattr(g, 'pg_db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Inicializa o banco de dados, criando as tabelas se elas não existirem.
    Isso deve ser chamado uma vez na inicialização da aplicação.
    """
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Tabela de usuários para autenticação
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                auth_token VARCHAR(255) NOT NULL UNIQUE
            )
        """)
        # Tabela de APIs, vinculada ao usuário
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apis (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(255) NOT NULL,
                public_key TEXT,
                secret_key TEXT,
                token TEXT,
                is_active BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE (user_id, name) -- Garante que um usuário não tenha duas APIs com o mesmo nome
            )
        """)
        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"Erro ao inicializar o banco de dados: {e}")
        if conn:
            conn.rollback() # Desfaz a transação em caso de erro
    finally:
        if conn:
            conn.close() # Garante que a conexão seja fechada

# Chame init_db() ao iniciar a aplicação para garantir que as tabelas existam
# Isso é importante para ambientes serverless onde o estado não é persistente
init_db()

# --- Funções de Autenticação e Utilitários ---
def get_user_id_from_token(token):
    """
    Busca o ID do usuário no banco de dados a partir do token de autenticação.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE auth_token = %s", (token,))
    user = cursor.fetchone()
    cursor.close()
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
    conn = get_db()
    cursor = conn.cursor()
    username = request.json.get('username')
    
    if not username:
        return jsonify({"message": "Username é obrigatório."}), 400
    
    try:
        auth_token = str(uuid.uuid4())
        cursor.execute("INSERT INTO users (username, auth_token) VALUES (%s, %s)", (username, auth_token))
        conn.commit()
        return jsonify({"message": "Usuário registrado com sucesso!", "username": username, "auth_token": auth_token}), 201
    except psycopg2.errors.UniqueViolation: # Erro específico para violação de UNIQUE no PostgreSQL
        conn.rollback() # Desfaz a transação
        return jsonify({"message": "Username já existe."}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"Erro ao registrar usuário: {e}"}), 500
    finally:
        cursor.close()

# --- Rotas de Gerenciamento de APIs ---
@app.route('/apis', methods=['GET', 'POST'])
@require_auth
def manage_apis(user_id):
    """
    Rota para adicionar uma nova API ou listar as APIs de um usuário.
    """
    conn = get_db()
    cursor = conn.cursor()

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
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, name, api_type, public_key, secret_key, token))
            conn.commit()
            return jsonify({"message": "API salva com sucesso!"}), 201
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return jsonify({"message": "Já existe uma API com este nome para este usuário."}), 400
        except Exception as e:
            conn.rollback()
            return jsonify({"message": f"Erro ao salvar API: {e}"}), 500
        finally:
            cursor.close()

    if request.method == 'GET':
        cursor.execute("SELECT id, name, is_active FROM apis WHERE user_id = %s", (user_id,))
        apis = [{"id": row['id'], "name": row['name'], "isActive": row['is_active']} for row in cursor.fetchall()]
        cursor.close()
        return jsonify(apis)

@app.route('/apis/set-active/<int:api_id>', methods=['POST'])
@require_auth
def set_active_api(user_id, api_id):
    """
    Rota para definir qual API de um usuário está ativa.
    """
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Desativa todas as APIs do usuário
        cursor.execute("UPDATE apis SET is_active = FALSE WHERE user_id = %s", (user_id,))
        
        # Ativa a API selecionada para o usuário
        cursor.execute("UPDATE apis SET is_active = TRUE WHERE id = %s AND user_id = %s", (api_id, user_id))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"message": "API não encontrada ou não pertence ao usuário."}), 404

        return jsonify({"message": f"API com ID {api_id} ativada."}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"Erro ao ativar API: {e}"}), 500
    finally:
        cursor.close()

# --- Rotas para Geração e Consulta de Pix ---
@app.route('/gerar-pix', methods=['POST'])
@require_auth
def gerar_pix(user_id):
    """
    Rota para gerar um Pix usando a API ativa do usuário.
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT name, type, public_key, secret_key, token FROM apis WHERE user_id = %s AND is_active = TRUE", (user_id,))
    active_api = cursor.fetchone()
    cursor.close()

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
            # Endpoint da Ghostpay para criar transações de compra
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
    conn = get_db()
    cursor = conn.cursor()
    transaction_id = request.args.get('transaction_id')

    if not transaction_id:
        return jsonify({"message": "ID da transação é obrigatório."}), 400

    cursor.execute("SELECT name, type, public_key, secret_key, token FROM apis WHERE user_id = %s AND is_active = TRUE", (user_id,))
    active_api = cursor.fetchone()
    cursor.close()

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

# O Vercel executa a aplicação diretamente, então o init_db() deve ser chamado no escopo global.
# Isso garante que as tabelas sejam criadas na primeira inicialização do contêiner.
# Removido o bloco if __name__ == '__main__': para ser compatível com Vercel.
