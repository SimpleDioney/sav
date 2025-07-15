import sqlite3
from flask import current_app, g
from werkzeug.security import generate_password_hash

DATABASE = 'database.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()

    
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_cliente TEXT NOT NULL,
            nome_cliente TEXT NOT NULL,
            numero_caixa TEXT NOT NULL DEFAULT '',
            store_id INTEGER,
            UNIQUE(codigo_cliente, store_id),
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_equipamento (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS marcas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            tipo_id INTEGER NOT NULL,
            FOREIGN KEY (tipo_id) REFERENCES tipos_equipamento(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tamanhos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patrimonio_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo_patrimonio TEXT NOT NULL,
            cliente_id INTEGER NOT NULL,
            tipo_id INTEGER NOT NULL,
            marca_id INTEGER NOT NULL,
            tamanho TEXT,
            UNIQUE(codigo_patrimonio, cliente_id),
            FOREIGN KEY (cliente_id) REFERENCES clientes(id) ON DELETE CASCADE,
            FOREIGN KEY (tipo_id) REFERENCES tipos_equipamento(id),
            FOREIGN KEY (marca_id) REFERENCES marcas(id)
        )
    ''')
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contas_a_pagar_diversos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero_caixa TEXT NOT NULL,
            store_id INTEGER,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
    ''')
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

    
    
    
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_marcas_nome_tipo ON marcas (nome, tipo_id);")

    
    
    
    tipos = ['Freezer', 'Forno', 'Estufa']
    for tipo in tipos:
        cursor.execute("INSERT OR IGNORE INTO tipos_equipamento (nome) VALUES (?)", (tipo,))
    db.commit() 
    
    
    
    freezer_id_result = cursor.execute("SELECT id FROM tipos_equipamento WHERE nome = 'Freezer'").fetchone()
    if freezer_id_result:
        freezer_id = freezer_id_result[0]
        marcas_freezer = ['Metalfrio', 'Fricon']
        for marca in marcas_freezer:
            cursor.execute("INSERT OR IGNORE INTO marcas (nome, tipo_id) VALUES (?, ?)", (marca, freezer_id))

    
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