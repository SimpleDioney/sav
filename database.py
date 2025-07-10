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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS store_departments (
            store_id INTEGER NOT NULL,
            department_role TEXT NOT NULL,
            FOREIGN KEY (store_id) REFERENCES stores (id) ON DELETE CASCADE,
            PRIMARY KEY (store_id, department_role)
        )
    ''')

    # --- TABELAS EXISTENTES MODIFICADAS ---
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
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN store_id INTEGER REFERENCES stores(id)")
    except sqlite3.OperationalError: pass

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
    except sqlite3.OperationalError: pass

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
    except sqlite3.OperationalError: pass

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
    except sqlite3.OperationalError: pass

    # Tabela para Cobrança: adicionada order_position
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cobranca_fichas_acerto (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ficha_acerto TEXT NOT NULL,
            caixa TEXT NOT NULL,
            range_cliente_inicio INTEGER NOT NULL,
            range_cliente_fim INTEGER NOT NULL,
            store_id INTEGER,
            order_position INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE cobranca_fichas_acerto ADD COLUMN store_id INTEGER REFERENCES stores(id)")
    except sqlite3.OperationalError: pass
    try:
        cursor.execute("ALTER TABLE cobranca_fichas_acerto ADD COLUMN order_position INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError: pass

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
    except sqlite3.OperationalError: pass


    # --- TABELA DE AUDITORIA ATUALIZADA ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            target_name TEXT,
            dados_antigos TEXT,
            dados_novos TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    # Adiciona novas colunas de forma segura
    try:
        cursor.execute("ALTER TABLE audit_log ADD COLUMN dados_antigos TEXT")
        cursor.execute("ALTER TABLE audit_log ADD COLUMN dados_novos TEXT")
    except sqlite3.OperationalError:
        pass


    # Adiciona um usuário SUPER ADMIN padrão SE NÃO EXISTIR
    cursor.execute("SELECT * FROM users WHERE username = 'Dioney'")
    if cursor.fetchone() is None:
        hashed_password = generate_password_hash('Dioney13')
        cursor.execute("INSERT INTO users (username, password, role, can_add_users, store_id) VALUES (?, ?, ?, ?, NULL)",
                       ('Dioney', hashed_password, 'super_admin', 1))
        db.commit()

def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()