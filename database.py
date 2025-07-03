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

    # Tabela de Patrimonios (mantida, mas com a coluna numero_caixa)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patrimonios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_cliente TEXT NOT NULL,
            nome_cliente TEXT NOT NULL,
            patrimonios TEXT NOT NULL,
            numero_caixa TEXT NOT NULL DEFAULT ''
        )
    ''')
    try:
        cursor.execute("ALTER TABLE patrimonios ADD COLUMN numero_caixa TEXT NOT NULL DEFAULT ''")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: numero_caixa" in str(e):
            pass
        else:
            raise

    # Tabela de Usuários (com role e can_add_users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin_patrimonio', -- super_admin, admin_rh, admin_patrimonio, admin_contas_a_pagar, admin_cobranca
            can_add_users INTEGER NOT NULL DEFAULT 0 -- 0 para false, 1 para true
        )
    ''')
    # Adicionar colunas se já existia a tabela users
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin_patrimonio'")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: role" in str(e):
            pass
        else:
            raise
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN can_add_users INTEGER NOT NULL DEFAULT 0")
        db.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name: can_add_users" in str(e):
            pass
        else:
            raise

    # Tabela para Contas a Pagar - Pagamentos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas_a_pagar_pagamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pagamento_data_inicio TEXT NOT NULL, -- DATA X
            pagamento_data_fim TEXT NOT NULL,    -- DATA Y
            caixa TEXT NOT NULL
        )
    ''')

    # Tabela para Contas a Pagar - Documentos Diversos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas_a_pagar_diversos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero_caixa TEXT NOT NULL
        )
    ''')

    # Tabela para Cobrança - Fichas de Acerto
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cobranca_fichas_acerto (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ficha_acerto TEXT NOT NULL,
            caixa TEXT NOT NULL,
            range_cliente_inicio INTEGER NOT NULL, -- Ex: 5100
            range_cliente_fim INTEGER NOT NULL     -- Ex: 5164
        )
    ''')

    # Tabela para RH (apenas placeholder por enquanto)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rh_dados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            -- Campos RH serão definidos depois
            placeholder TEXT
        )
    ''')

    # Adiciona um usuário SUPER ADMIN padrão SE NÃO EXISTIR
    cursor.execute("SELECT * FROM users WHERE username = 'Dioney'")
    if cursor.fetchone() is None:
        # ATENÇÃO: MUDE 'superadmin_senha_forte' PARA UMA SENHA REALMENTE SEGURA!
        hashed_password = generate_password_hash('Dioney13')
        cursor.execute("INSERT INTO users (username, password, role, can_add_users) VALUES (?, ?, ?, ?)",
                       ('Dioney', hashed_password, 'super_admin', 1)) # Super Admin pode adicionar usuários
        db.commit()
    else:
        pass # Usuário já existe, ignora a inserção

def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

def reset_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS patrimonios')
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS contas_a_pagar_pagamentos')
    cursor.execute('DROP TABLE IF EXISTS contas_a_pagar_diversos')
    cursor.execute('DROP TABLE IF EXISTS cobranca_fichas_acerto')
    cursor.execute('DROP TABLE IF EXISTS rh_dados')
    conn.close()
    init_db()
    print("Banco de dados resetado e tabelas recriadas.")