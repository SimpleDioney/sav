# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_app, get_db, close_db, DATABASE
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui_E_MUITO_LONGA_E_RANDOMICA_PARA_PRODUCAO' # MUDE ISSO!

# Inicializa o banco de dados com o app Flask
init_app(app)

# --- Decoradores de Permissão ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Você precisa fazer login para acessar esta página.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session or 'role' not in session:
                flash('Você precisa fazer login para acessar esta página.', 'danger')
                return redirect(url_for('admin_login'))
            
            if session['role'] not in allowed_roles:
                flash('Você não tem permissão para acessar esta página.', 'danger')
                if session.get('role') == 'super_admin':
                    return redirect(url_for('super_admin_dashboard'))
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Rotas Frontend (Público) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    search_by = request.args.get('search_by', 'codigo_cliente')
    results = []
    
    if query:
        db = get_db()
        if search_by == 'codigo_cliente':
            results = db.execute("SELECT * FROM patrimonios WHERE codigo_cliente LIKE ?", ('%' + query + '%',)).fetchall()
        elif search_by == 'nome_cliente':
            results = db.execute("SELECT * FROM patrimonios WHERE nome_cliente LIKE ?", ('%' + query + '%',)).fetchall()
        elif search_by == 'patrimonio_especifico':
            all_items = db.execute("SELECT * FROM patrimonios").fetchall()
            for row in all_items:
                if any(query.lower() in p.strip().lower() for p in row['patrimonios'].split('/')):
                    results.append(row)
        elif search_by == 'caixa_cobranca_range':
            try:
                cliente_num = int(query)
                results = db.execute("SELECT * FROM cobranca_fichas_acerto WHERE ? BETWEEN range_cliente_inicio AND range_cliente_fim", (cliente_num,)).fetchall()
            except ValueError:
                flash('Para pesquisa por "Caixa Cobrança", digite um número de cliente válido.', 'danger')
    
    return render_template('search_results.html', results=results, query=query, search_by=search_by)

# --- Rotas Admin (Gerais) ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute("SELECT u.*, s.name as store_name FROM users u LEFT JOIN stores s ON u.store_id = s.id WHERE u.username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            session['store_id'] = user['store_id']
            session['store_name'] = user['store_name']
            flash(f'Login realizado com sucesso!', 'success')
            
            if user['role'] == 'super_admin': return redirect(url_for('super_admin_dashboard'))
            if user['role'] == 'admin_patrimonio': return redirect(url_for('patrimonio_dashboard'))
            if user['role'] == 'admin_rh': return redirect(url_for('rh_dashboard'))
            if user['role'] == 'admin_contas_a_pagar': return redirect(url_for('contas_a_pagar_dashboard'))
            if user['role'] == 'admin_cobranca': return redirect(url_for('cobranca_dashboard'))
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('admin_login'))

# --- Rotas SUPER ADMIN ---

@app.route('/super_admin/dashboard')
@login_required
@role_required(['super_admin'])
def super_admin_dashboard():
    return render_template('super_admin/super_admin_dashboard.html')

@app.route('/super_admin/users', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin'])
def user_management():
    db = get_db()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        store_id = request.form.get('store_id')
        store_id = int(store_id) if store_id else None
        can_add_users = 1 if 'can_add_users' in request.form else 0

        if not all([username, password, role]):
            flash('Usuário, senha e função são obrigatórios!', 'danger')
        else:
            try:
                hashed_password = generate_password_hash(password)
                db.execute("INSERT INTO users (username, password, role, can_add_users, store_id) VALUES (?, ?, ?, ?, ?)",
                           (username, hashed_password, role, can_add_users, store_id))
                db.commit()
                flash(f'Usuário {username} criado com sucesso!', 'success')
            except sqlite3.IntegrityError:
                flash(f'Erro: Usuário "{username}" já existe.', 'danger')
        return redirect(url_for('user_management'))

    users = db.execute("SELECT u.id, u.username, u.role, u.can_add_users, s.name as store_name FROM users u LEFT JOIN stores s ON u.store_id = s.id ORDER BY u.username").fetchall()
    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    return render_template('super_admin/user_management.html', users=users, stores=stores)

@app.route('/super_admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['super_admin'])
def delete_user(user_id):
    db = get_db()
    user_to_delete = db.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['role'] == 'super_admin':
        flash('Não é possível excluir um Super Admin.', 'danger')
    else:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('user_management'))

@app.route('/super_admin/stores', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin'])
def manage_stores():
    db = get_db()
    available_departments = ['admin_rh', 'admin_patrimonio', 'admin_contas_a_pagar', 'admin_cobranca']

    if request.method == 'POST':
        store_name = request.form.get('name', '').strip()
        selected_departments = request.form.getlist('departments')
        if not store_name or not selected_departments:
            flash('O nome da loja e pelo menos um departamento são obrigatórios.', 'danger')
        else:
            try:
                cursor = db.cursor()
                cursor.execute("INSERT INTO stores (name) VALUES (?)", (store_name,))
                store_id = cursor.lastrowid
                for dept_role in selected_departments:
                    cursor.execute("INSERT INTO store_departments (store_id, department_role) VALUES (?, ?)", (store_id, dept_role))
                db.commit()
                flash(f'Loja "{store_name}" criada com sucesso!', 'success')
            except sqlite3.IntegrityError:
                flash(f'Erro: A loja "{store_name}" já existe.', 'danger')
        return redirect(url_for('manage_stores'))

    stores_data = db.execute("""
        SELECT s.id, s.name, GROUP_CONCAT(sd.department_role, ', ') as departments
        FROM stores s
        LEFT JOIN store_departments sd ON s.id = sd.store_id
        GROUP BY s.id, s.name ORDER BY s.name
    """).fetchall()
    return render_template('super_admin/manage_stores.html', stores=stores_data, available_departments=available_departments)

@app.route('/super_admin/stores/delete/<int:store_id>', methods=['POST'])
@login_required
@role_required(['super_admin'])
def delete_store(store_id):
    db = get_db()
    db.execute("UPDATE users SET store_id = NULL WHERE store_id = ?", (store_id,))
    db.execute("DELETE FROM stores WHERE id = ?", (store_id,))
    db.commit()
    flash('Loja excluída com sucesso!', 'success')
    return redirect(url_for('manage_stores'))

# --- Rotas PATRIMÔNIO ---

@app.route('/patrimonio/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_dashboard():
    db = get_db()
    if request.method == 'POST':
        store_id = None
        if session['role'] == 'super_admin':
            store_id = request.form.get('store_id')
            if not store_id:
                flash('Como Super Admin, você deve selecionar uma loja.', 'danger')
                return redirect(url_for('patrimonio_dashboard'))
        else:
            store_id = session.get('store_id')

        form_data = (request.form['codigo_cliente'], request.form['nome_cliente'], request.form['patrimonios'], request.form['numero_caixa'], store_id)
        db.execute("INSERT INTO patrimonios (codigo_cliente, nome_cliente, patrimonios, numero_caixa, store_id) VALUES (?, ?, ?, ?, ?)", form_data)
        db.commit()
        flash('Patrimônio adicionado com sucesso!', 'success')
        return redirect(url_for('patrimonio_dashboard'))

    stores = []
    if session['role'] == 'super_admin':
        all_patrimonios = db.execute("SELECT p.*, s.name as store_name FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id ORDER BY p.codigo_cliente").fetchall()
        stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    else:
        all_patrimonios = db.execute("SELECT p.*, s.name as store_name FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id WHERE p.store_id = ? ORDER BY p.codigo_cliente", (session.get('store_id'),)).fetchall()
    
    return render_template('patrimonio/patrimonio_dashboard.html', patrimonios=all_patrimonios, stores=stores)

@app.route('/patrimonio/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM patrimonios WHERE id = ?", (item_id,)).fetchone()
    
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Patrimônio não encontrado ou sem permissão para editar.', 'danger')
        return redirect(url_for('patrimonio_dashboard'))

    if request.method == 'POST':
        form_data = (request.form['codigo_cliente'], request.form['nome_cliente'], request.form['patrimonios'], request.form['numero_caixa'], item_id)
        db.execute("UPDATE patrimonios SET codigo_cliente = ?, nome_cliente = ?, patrimonios = ?, numero_caixa = ? WHERE id = ?", form_data)
        db.commit()
        flash('Patrimônio atualizado com sucesso!', 'success')
        return redirect(url_for('patrimonio_dashboard'))
        
    return render_template('patrimonio/patrimonio_edit.html', item=item)

@app.route('/patrimonio/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_delete(item_id):
    db = get_db()
    item = db.execute("SELECT store_id FROM patrimonios WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Patrimônio não encontrado ou sem permissão para excluir.', 'danger')
    else:
        db.execute("DELETE FROM patrimonios WHERE id = ?", (item_id,))
        db.commit()
        flash('Patrimônio excluído com sucesso!', 'success')
    return redirect(url_for('patrimonio_dashboard'))

# --- Rotas RH (Placeholder) ---
@app.route('/rh/dashboard')
@login_required
@role_required(['super_admin', 'admin_rh'])
def rh_dashboard():
    # TODO: Implementar CRUD e isolamento por store_id como no módulo de Patrimônio
    return render_template('rh/rh_dashboard.html')

# --- Rotas Contas a Pagar - Pagamentos ---
@app.route('/contas_a_pagar/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_dashboard():
    db = get_db()
    if request.method == 'POST':
        store_id = None
        if session['role'] == 'super_admin':
            store_id = request.form.get('store_id')
            if not store_id:
                flash('Como Super Admin, você deve selecionar uma loja.', 'danger')
                return redirect(url_for('contas_a_pagar_dashboard'))
        else:
            store_id = session.get('store_id')
            
        form_data = (request.form['pagamento_data_inicio'], request.form['pagamento_data_fim'], request.form['caixa'], store_id)
        db.execute("INSERT INTO contas_a_pagar_pagamentos (pagamento_data_inicio, pagamento_data_fim, caixa, store_id) VALUES (?, ?, ?, ?)", form_data)
        db.commit()
        flash('Pagamento adicionado com sucesso!', 'success'
              )
        return redirect(url_for('contas_a_pagar_dashboard'))

    stores = []
    if session['role'] == 'super_admin':
        pagamentos = db.execute("SELECT p.*, s.name as store_name FROM contas_a_pagar_pagamentos p LEFT JOIN stores s ON p.store_id = s.id ORDER BY p.pagamento_data_inicio DESC").fetchall()
        stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    else:
        pagamentos = db.execute("SELECT p.*, s.name as store_name FROM contas_a_pagar_pagamentos p LEFT JOIN stores s ON p.store_id = s.id WHERE p.store_id = ? ORDER BY p.pagamento_data_inicio DESC", (session.get('store_id'),)).fetchall()

    pagamentos = [dict(row) for row in pagamentos]

    for item in pagamentos:
        try:
            print("INICIO:", item['pagamento_data_inicio'])
            print("FIM:", item['pagamento_data_fim'])
            item['pagamento_data_inicio'] = datetime.strptime(item['pagamento_data_inicio'], '%Y-%m-%d').strftime('%d/%m/%Y')
            item['pagamento_data_fim'] = datetime.strptime(item['pagamento_data_fim'], '%Y-%m-%d').strftime('%d/%m/%Y')
        except Exception as e:
            print("Erro ao formatar data:", e)


    return render_template('contas_a_pagar/contas_a_pagar_dashboard.html', pagamentos=pagamentos, stores=stores)

@app.route('/contas_a_pagar/pagamentos/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,)).fetchone()

    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Registro não encontrado ou sem permissão para editar.', 'danger')
        return redirect(url_for('contas_a_pagar_dashboard'))

    if request.method == 'POST':
        form_data = (request.form['pagamento_data_inicio'], request.form['pagamento_data_fim'], request.form['caixa'], item_id)
        db.execute("UPDATE contas_a_pagar_pagamentos SET pagamento_data_inicio = ?, pagamento_data_fim = ?, caixa = ? WHERE id = ?", form_data)
        db.commit()
        flash('Registro atualizado com sucesso!', 'success')
        return redirect(url_for('contas_a_pagar_dashboard'))
        
    return render_template('contas_a_pagar/contas_a_pagar_pagamentos_edit.html', item=item)

@app.route('/contas_a_pagar/pagamentos/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_delete(item_id):
    db = get_db()
    item = db.execute("SELECT store_id FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Registro não encontrado ou sem permissão para excluir.', 'danger')
    else:
        db.execute("DELETE FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,))
        db.commit()
        flash('Registro excluído com sucesso!', 'success')
    return redirect(url_for('contas_a_pagar_dashboard'))

# --- Rotas Contas a Pagar - Documentos Diversos ---
@app.route('/contas_a_pagar/documentos_diversos', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def documentos_diversos_dashboard():
    db = get_db()
    if request.method == 'POST':
        store_id = None
        if session['role'] == 'super_admin':
            store_id = request.form.get('store_id')
            if not store_id:
                flash('Como Super Admin, você deve selecionar uma loja.', 'danger')
                return redirect(url_for('documentos_diversos_dashboard'))
        else:
            store_id = session.get('store_id')

        db.execute("INSERT INTO contas_a_pagar_diversos (numero_caixa, store_id) VALUES (?, ?)", (request.form['numero_caixa'], store_id))
        db.commit()
        flash('Documento diverso adicionado com sucesso!', 'success')
        return redirect(url_for('documentos_diversos_dashboard'))

    stores = []
    if session['role'] == 'super_admin':
        documentos = db.execute("SELECT d.*, s.name as store_name FROM contas_a_pagar_diversos d LEFT JOIN stores s ON d.store_id = s.id ORDER BY d.numero_caixa").fetchall()
        stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    else:
        documentos = db.execute("SELECT d.*, s.name as store_name FROM contas_a_pagar_diversos d LEFT JOIN stores s ON d.store_id = s.id WHERE d.store_id = ? ORDER BY d.numero_caixa", (session.get('store_id'),)).fetchall()
    
    return render_template('contas_a_pagar/documentos_diversos_dashboard.html', documentos_diversos=documentos, stores=stores)

@app.route('/contas_a_pagar/documentos_diversos/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_diversos WHERE id = ?", (item_id,)).fetchone()

    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Documento não encontrado ou sem permissão para editar.', 'danger')
        return redirect(url_for('documentos_diversos_dashboard'))

    if request.method == 'POST':
        db.execute("UPDATE contas_a_pagar_diversos SET numero_caixa = ? WHERE id = ?", (request.form['numero_caixa'], item_id))
        db.commit()
        flash('Documento atualizado com sucesso!', 'success')
        return redirect(url_for('documentos_diversos_dashboard'))

    return render_template('contas_a_pagar/documentos_diversos_edit.html', item=item)

@app.route('/contas_a_pagar/documentos_diversos/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_delete(item_id):
    db = get_db()
    item = db.execute("SELECT store_id FROM contas_a_pagar_diversos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Documento não encontrado ou sem permissão para excluir.', 'danger')
    else:
        db.execute("DELETE FROM contas_a_pagar_diversos WHERE id = ?", (item_id,))
        db.commit()
        flash('Documento excluído com sucesso!', 'success')
    return redirect(url_for('documentos_diversos_dashboard'))

# --- Rotas Cobrança ---
@app.route('/cobranca/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_dashboard():
    db = get_db()
    if request.method == 'POST':
        store_id = None
        if session['role'] == 'super_admin':
            store_id = request.form.get('store_id')
            if not store_id:
                flash('Como Super Admin, você deve selecionar uma loja.', 'danger')
                return redirect(url_for('cobranca_dashboard'))
        else:
            store_id = session.get('store_id')
            
        try:
            form_data = (
                request.form['ficha_acerto'],
                request.form['caixa'],
                int(request.form['range_cliente_inicio']),
                int(request.form['range_cliente_fim']),
                store_id
            )
            db.execute("INSERT INTO cobranca_fichas_acerto (ficha_acerto, caixa, range_cliente_inicio, range_cliente_fim, store_id) VALUES (?, ?, ?, ?, ?)", form_data)
            db.commit()
            flash('Ficha de Acerto adicionada com sucesso!', 'success')
        except ValueError:
            flash('Os campos de range de cliente devem ser números.', 'danger')
        return redirect(url_for('cobranca_dashboard'))

    stores = []
    if session['role'] == 'super_admin':
        fichas = db.execute("SELECT f.*, s.name as store_name FROM cobranca_fichas_acerto f LEFT JOIN stores s ON f.store_id = s.id ORDER BY f.ficha_acerto").fetchall()
        stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    else:
        fichas = db.execute("SELECT f.*, s.name as store_name FROM cobranca_fichas_acerto f LEFT JOIN stores s ON f.store_id = s.id WHERE f.store_id = ? ORDER BY f.ficha_acerto", (session.get('store_id'),)).fetchall()
        
    return render_template('cobranca/cobranca_dashboard.html', fichas_acerto=fichas, stores=stores)

@app.route('/cobranca/fichas_acerto/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM cobranca_fichas_acerto WHERE id = ?", (item_id,)).fetchone()

    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Ficha de Acerto não encontrada ou sem permissão para editar.', 'danger')
        return redirect(url_for('cobranca_dashboard'))

    if request.method == 'POST':
        try:
            form_data = (
                request.form['ficha_acerto'],
                request.form['caixa'],
                int(request.form['range_cliente_inicio']),
                int(request.form['range_cliente_fim']),
                item_id
            )
            db.execute("UPDATE cobranca_fichas_acerto SET ficha_acerto = ?, caixa = ?, range_cliente_inicio = ?, range_cliente_fim = ? WHERE id = ?", form_data)
            db.commit()
            flash('Ficha de Acerto atualizada com sucesso!', 'success')
        except ValueError:
            flash('Os campos de range de cliente devem ser números.', 'danger')
        return redirect(url_for('cobranca_dashboard'))

    return render_template('cobranca/cobranca_fichas_acerto_edit.html', item=item)

@app.route('/cobranca/fichas_acerto/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_delete(item_id):
    db = get_db()
    item = db.execute("SELECT store_id FROM cobranca_fichas_acerto WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Ficha de Acerto não encontrada ou sem permissão para excluir.', 'danger')
    else:
        db.execute("DELETE FROM cobranca_fichas_acerto WHERE id = ?", (item_id,))
        db.commit()
        flash('Ficha de Acerto excluída com sucesso!', 'success')
    return redirect(url_for('cobranca_dashboard'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
