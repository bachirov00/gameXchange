from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import jwt
import bcrypt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-in-production'

# Base de données SQLite pour le développement
DATABASE = 'gameXchange.db'

def init_db():
    """Initialise la base de données avec les tables nécessaires"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Table des utilisateurs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            kyc_level TEXT DEFAULT 'Basic',
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table des comptes gaming
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS game_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            game TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            currency TEXT DEFAULT 'EUR',
            level TEXT,
            platform TEXT,
            features TEXT,
            status TEXT DEFAULT 'available',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )
    ''')
    
    # Table des transactions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            currency TEXT NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            fees DECIMAL(10,2) DEFAULT 0,
            status TEXT DEFAULT 'pending',
            method TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table des portefeuilles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            currency TEXT NOT NULL,
            balance DECIMAL(18,8) DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, currency)
        )
    ''')
    
    conn.commit()
    conn.close()

# Routes d'authentification
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Inscription d'un nouvel utilisateur"""
    data = request.get_json()
    
    try:
        # Validation des données
        required_fields = ['email', 'password', 'firstName', 'lastName']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Le champ {field} est requis'}), 400
        
        # Hachage du mot de passe
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Insertion en base
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES (?, ?, ?, ?)
        ''', (data['email'], password_hash, data['firstName'], data['lastName']))
        
        user_id = cursor.lastrowid
        
        # Initialisation du portefeuille
        currencies = ['USD', 'EUR', 'MAD', 'BTC', 'ETH', 'USDT', 'BNB']
        for currency in currencies:
            cursor.execute('''
                INSERT INTO wallets (user_id, currency, balance)
                VALUES (?, ?, 0)
            ''', (user_id, currency))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Utilisateur créé avec succès', 'user_id': user_id}), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Cet email est déjà utilisé'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Connexion d'un utilisateur"""
    data = request.get_json()
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2]):
            # Génération du token JWT
            token = jwt.encode({
                'user_id': user[0],
                'email': user[1],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': {
                    'id': user[0],
                    'email': user[1],
                    'firstName': user[3],
                    'lastName': user[4],
                    'kycLevel': user[5],
                    'twoFactorEnabled': user[6]
                }
            }), 200
        else:
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Routes des jeux et comptes
@app.route('/api/games/accounts', methods=['GET'])
def get_game_accounts():
    """Récupère la liste des comptes gaming"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ga.*, u.first_name, u.last_name 
            FROM game_accounts ga
            JOIN users u ON ga.seller_id = u.id
            WHERE ga.status = 'available'
            ORDER BY ga.created_at DESC
        ''')
        
        accounts = cursor.fetchall()
        
        result = []
        for account in accounts:
            result.append({
                'id': account[0],
                'game': account[2],
                'title': account[3],
                'description': account[4],
                'price': account[5],
                'currency': account[6],
                'level': account[7],
                'platform': account[8],
                'features': account[9].split(',') if account[9] else [],
                'seller': {
                    'name': f"{account[11]} {account[12]}",
                    'verified': True
                }
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/games/accounts', methods=['POST'])
def create_game_account():
    """Crée une nouvelle annonce de compte gaming"""
    data = request.get_json()
    
    try:
        # Ici on devrait vérifier le token JWT
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO game_accounts (seller_id, game, title, description, price, currency, level, platform, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('seller_id', 1),  # À remplacer par l'ID du token JWT
            data['game'],
            data['title'],
            data.get('description', ''),
            data['price'],
            data.get('currency', 'EUR'),
            data.get('level', ''),
            data.get('platform', ''),
            ','.join(data.get('features', []))
        ))
        
        account_id = cursor.lastrowid
        conn.commit()
        
        return jsonify({'message': 'Compte créé avec succès', 'account_id': account_id}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Routes du portefeuille
@app.route('/api/wallet/balance', methods=['GET'])
def get_wallet_balance():
    """Récupère les soldes du portefeuille"""
    try:
        # Ici on devrait récupérer l'user_id du token JWT
        user_id = 1  # Exemple
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT currency, balance FROM wallets WHERE user_id = ?', (user_id,))
        balances = cursor.fetchall()
        
        result = {}
        for currency, balance in balances:
            result[currency] = float(balance)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/wallet/deposit', methods=['POST'])
def deposit_funds():
    """Dépose des fonds dans le portefeuille"""
    data = request.get_json()
    
    try:
        user_id = 1  # À remplacer par l'ID du token JWT
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Mise à jour du solde
        cursor.execute('''
            UPDATE wallets 
            SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND currency = ?
        ''', (data['amount'], user_id, data['currency']))
        
        # Enregistrement de la transaction
        cursor.execute('''
            INSERT INTO transactions (user_id, type, currency, amount, method, status)
            VALUES (?, 'deposit', ?, ?, ?, 'completed')
        ''', (user_id, data['currency'], data['amount'], data.get('method', 'stripe')))
        
        conn.commit()
        
        return jsonify({'message': 'Dépôt effectué avec succès'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/wallet/transactions', methods=['GET'])
def get_transactions():
    """Récupère l'historique des transactions"""
    try:
        user_id = 1  # À remplacer par l'ID du token JWT
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT type, currency, amount, fees, status, method, created_at
            FROM transactions 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (user_id,))
        
        transactions = cursor.fetchall()
        
        result = []
        for tx in transactions:
            result.append({
                'type': tx[0],
                'currency': tx[1],
                'amount': float(tx[2]),
                'fees': float(tx[3]),
                'status': tx[4],
                'method': tx[5],
                'date': tx[6]
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Route de santé
@app.route('/api/health', methods=['GET'])
def health_check():
    """Vérification de l'état de l'API"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

if __name__ == '__main__':
    # Initialisation de la base de données
    init_db()
    
    # Démarrage du serveur
    app.run(host='0.0.0.0', port=5000, debug=True)

