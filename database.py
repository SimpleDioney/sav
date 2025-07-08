# database.py
import sqlite3
from flask import current_app, g
from werkzeug.security import generate_password_hash

DATABASE = 'database.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()

    # --- ESTRUTURA DE LOJAS ---
    # Tabela para armazenar as lojas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')

    # Tabela para relacionar lojas com seus departamentos (roles)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS store_departments (
            store_id INTEGER NOT NULL,
            department_role TEXT NOT NULL,
            FOREIGN KEY (store_id) REFERENCES stores (id) ON DELETE CASCADE,
            PRIMARY KEY (store_id, department_role)
        )
    ''')

    # --- TABELAS EXISTENTES MODIFICADAS ---

    # Tabela de Usuários: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin_patrimonio',
            can_add_users INTEGER NOT NULL DEFAULT 0,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    # Bloco para adicionar a coluna store_id de forma segura, sem dar erro se já existir
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise

    # Tabela de Patrimonios: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patrimonios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_cliente TEXT NOT NULL,
            nome_cliente TEXT NOT NULL,
            patrimonios TEXT NOT NULL,
            numero_caixa TEXT NOT NULL DEFAULT '',
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE patrimonios ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise


    # Tabela para Contas a Pagar - Pagamentos: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas_a_pagar_pagamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pagamento_data_inicio TEXT NOT NULL,
            pagamento_data_fim TEXT NOT NULL,
            caixa TEXT NOT NULL,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE contas_a_pagar_pagamentos ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise

    # Tabela para Contas a Pagar - Documentos Diversos: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas_a_pagar_diversos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero_caixa TEXT NOT NULL,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE contas_a_pagar_diversos ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise

    # Tabela para Cobrança - Fichas de Acerto: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cobranca_fichas_acerto (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ficha_acerto TEXT NOT NULL,
            caixa TEXT NOT NULL,
            range_cliente_inicio INTEGER NOT NULL,
            range_cliente_fim INTEGER NOT NULL,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE cobranca_fichas_acerto ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise

    # Tabela para RH: adicionada a referência à loja (store_id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rh_dados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            placeholder TEXT,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE rh_dados ADD COLUMN store_id INTEGER REFERENCES stores(id)")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: store_id" in str(e):
            pass
        else:
            raise

    # Tabela de Log de Auditoria
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            target_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')


    # Adiciona um usuário SUPER ADMIN padrão SE NÃO EXISTIR
    cursor.execute("SELECT * FROM users WHERE username = 'Dioney'")
    if cursor.fetchone() is None:
        hashed_password = generate_password_hash('Dioney13')
        # O super admin não precisa de loja (store_id é NULL)
        cursor.execute("INSERT INTO users (username, password, role, can_add_users, store_id) VALUES (?, ?, ?, ?, NULL)",
                       ('Dioney', hashed_password, 'super_admin', 1))
        db.commit()

def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

def reset_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Ordem de exclusão é importante por causa das chaves estrangeiras
    cursor.execute('DROP TABLE IF EXISTS store_departments')
    cursor.execute('DROP TABLE IF EXISTS patrimonios')
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS contas_a_pagar_pagamentos')
    cursor.execute('DROP TABLE IF EXISTS contas_a_pagar_diversos')
    cursor.execute('DROP TABLE IF EXISTS cobranca_fichas_acerto')
    cursor.execute('DROP TABLE IF EXISTS rh_dados')
    cursor.execute('DROP TABLE IF EXISTS stores') # Exclui a tabela de lojas por último
    cursor.execute('DROP TABLE IF EXISTS audit_log')
    conn.close()
    
    # Recria o banco do zero
    with current_app.app_context():
        init_db()
    print("Banco de dados resetado e todas as tabelas, incluindo as de lojas, foram recriadas.")