# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_app, get_db, close_db, DATABASE

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
            if 'logged_in' not in session:
                flash('Você precisa fazer login para acessar esta página.', 'danger')
                return redirect(url_for('admin_login'))
            
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT role FROM users WHERE username = ?", (session['username'],))
            user_role = cursor.fetchone()['role']
            
            if user_role not in allowed_roles:
                flash('Você não tem permissão para acessar esta página.', 'danger')
                return redirect(url_for('index')) # Ou para o dashboard do usuário
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def can_add_users_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Você precisa fazer login para acessar esta página.', 'danger')
            return redirect(url_for('admin_login'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT can_add_users FROM users WHERE username = ?", (session['username'],))
        can_add = cursor.fetchone()['can_add_users']
        
        if not can_add:
            flash('Você não tem permissão para criar novos usuários.', 'danger')
            return redirect(url_for('index')) # Ou para o dashboard do usuário
        return f(*args, **kwargs)
    return decorated_function

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
        cursor = db.cursor()
        
        if search_by == 'codigo_cliente':
            cursor.execute("SELECT * FROM patrimonios WHERE codigo_cliente LIKE ?", ('%' + query + '%',))
            results = cursor.fetchall()
        elif search_by == 'nome_cliente':
            cursor.execute("SELECT * FROM patrimonios WHERE nome_cliente LIKE ?", ('%' + query + '%',))
            results = cursor.fetchall()
        elif search_by == 'patrimonio_especifico':
            cursor.execute("SELECT * FROM patrimonios")
            all_patrimonios = cursor.fetchall()
            
            for row in all_patrimonios:
                patrimonios_list = [p.strip().lower() for p in row['patrimonios'].split('/')]
                if any(query.lower() in p for p in patrimonios_list):
                    results.append(row)
        elif search_by == 'caixa_cobranca_range': # Nova lógica de pesquisa para Cobrança
            try:
                # Assume que a query é um número de cliente, e busca o range
                cliente_num = int(query)
                cursor.execute("SELECT * FROM cobranca_fichas_acerto WHERE ? BETWEEN range_cliente_inicio AND range_cliente_fim", (cliente_num,))
                results = cursor.fetchall()
            except ValueError:
                flash('Para pesquisa por "Caixa Cobrança (Range)", digite um número de cliente válido.', 'danger')
                results = []
        
    return render_template('search_results.html', results=results, query=query, search_by=search_by)

# --- Rotas Admin (Gerais) ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Login realizado com sucesso como {user["role"]}!', 'success')
            
            if user['role'] == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))
            elif user['role'] == 'admin_patrimonio':
                return redirect(url_for('patrimonio_dashboard'))
            elif user['role'] == 'admin_rh':
                return redirect(url_for('rh_dashboard'))
            elif user['role'] == 'admin_contas_a_pagar':
                return redirect(url_for('contas_a_pagar_dashboard'))
            elif user['role'] == 'admin_cobranca':
                return redirect(url_for('cobranca_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('admin_login'))

# --- Rotas SUPER ADMIN ---

@app.route('/super_admin/dashboard')
@role_required(['super_admin'])
def super_admin_dashboard():
    return render_template('super_admin/super_admin_dashboard.html')

@app.route('/super_admin/users', methods=['GET', 'POST'])
@role_required(['super_admin'])
@can_add_users_required
def user_management():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        can_add_users = 1 if request.form.get('can_add_users') == 'on' else 0

        if not all([username, password, role]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            try:
                hashed_password = generate_password_hash(password)
                cursor.execute("INSERT INTO users (username, password, role, can_add_users) VALUES (?, ?, ?, ?)",
                               (username, hashed_password, role, can_add_users))
                db.commit()
                flash(f'Usuário {username} criado com sucesso!', 'success')
            except sqlite3.IntegrityError:
                flash(f'Erro: Usuário "{username}" já existe.', 'danger')
            except Exception as e:
                flash(f'Erro ao criar usuário: {e}', 'danger')

    cursor.execute("SELECT id, username, role, can_add_users FROM users ORDER BY username")
    users = cursor.fetchall()

    return render_template('super_admin/user_management.html', users=users)

@app.route('/super_admin/users/delete/<int:user_id>', methods=['POST'])
@role_required(['super_admin'])
def delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
    user_to_delete = cursor.fetchone()
    if user_to_delete and user_to_delete['role'] == 'super_admin' and user_to_delete['username'] == session['username']:
        flash('Você não pode excluir sua própria conta de Super Admin.', 'danger')
    else:
        try:
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            flash('Usuário excluído com sucesso!', 'success')
        except Exception as e:
            flash(f'Erro ao excluir usuário: {e}', 'danger')
    
    return redirect(url_for('user_management'))

# --- Rotas PATRIMÔNIO (Mantidas) ---

@app.route('/patrimonio/dashboard', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_dashboard():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        codigo_cliente = request.form['codigo_cliente'].strip()
        nome_cliente = request.form['nome_cliente'].strip()
        patrimonios = request.form['patrimonios'].strip()
        numero_caixa = request.form['numero_caixa'].strip()

        if not all([codigo_cliente, nome_cliente, patrimonios, numero_caixa]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            try:
                cursor.execute("INSERT INTO patrimonios (codigo_cliente, nome_cliente, patrimonios, numero_caixa) VALUES (?, ?, ?, ?)",
                               (codigo_cliente, nome_cliente, patrimonios, numero_caixa))
                db.commit()
                flash('Patrimônio adicionado com sucesso!', 'success')
            except sqlite3.IntegrityError:
                flash('Erro ao adicionar patrimônio. Verifique os dados.', 'danger')
    
    cursor.execute("SELECT * FROM patrimonios ORDER BY codigo_cliente")
    all_patrimonios = cursor.fetchall()
    
    return render_template('patrimonio/patrimonio_dashboard.html', patrimonios=all_patrimonios)

@app.route('/patrimonio/edit/<int:item_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_edit(item_id):
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        codigo_cliente = request.form['codigo_cliente'].strip()
        nome_cliente = request.form['nome_cliente'].strip()
        patrimonios = request.form['patrimonios'].strip()
        numero_caixa = request.form['numero_caixa'].strip()
        
        if not all([codigo_cliente, nome_cliente, patrimonios, numero_caixa]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            cursor.execute("UPDATE patrimonios SET codigo_cliente = ?, nome_cliente = ?, patrimonios = ?, numero_caixa = ? WHERE id = ?",
                           (codigo_cliente, nome_cliente, patrimonios, numero_caixa, item_id))
            db.commit()
            flash('Patrimônio atualizado com sucesso!', 'success')
            return redirect(url_for('patrimonio_dashboard'))
    
    cursor.execute("SELECT * FROM patrimonios WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    
    if item is None:
        flash('Patrimônio não encontrado.', 'danger')
        return redirect(url_for('patrimonio_dashboard'))
        
    return render_template('patrimonio/patrimonio_edit.html', item=item)

@app.route('/patrimonio/delete/<int:item_id>', methods=['POST'])
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_delete(item_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM patrimonios WHERE id = ?", (item_id,))
    db.commit()
    flash('Patrimônio excluído com sucesso!', 'success')
    return redirect(url_for('patrimonio_dashboard'))

# --- Rotas RH (Placeholder) ---
@app.route('/rh/dashboard')
@role_required(['super_admin', 'admin_rh'])
def rh_dashboard():
    # Lógica para RH aqui
    return render_template('rh/rh_dashboard.html')

# --- Rotas Contas a Pagar - Pagamentos ---
@app.route('/contas_a_pagar/dashboard', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_dashboard():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        pagamento_data_inicio = request.form['pagamento_data_inicio'].strip()
        pagamento_data_fim = request.form['pagamento_data_fim'].strip()
        caixa = request.form['caixa'].strip()

        if not all([pagamento_data_inicio, pagamento_data_fim, caixa]):
            flash('Todos os campos de Pagamentos são obrigatórios!', 'danger')
        else:
            try:
                cursor.execute("INSERT INTO contas_a_pagar_pagamentos (pagamento_data_inicio, pagamento_data_fim, caixa) VALUES (?, ?, ?)",
                               (pagamento_data_inicio, pagamento_data_fim, caixa))
                db.commit()
                flash('Pagamento adicionado com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao adicionar pagamento: {e}', 'danger')
    
    cursor.execute("SELECT * FROM contas_a_pagar_pagamentos ORDER BY pagamento_data_inicio DESC")
    pagamentos = cursor.fetchall()

    return render_template('contas_a_pagar/contas_a_pagar_dashboard.html', pagamentos=pagamentos)

@app.route('/contas_a_pagar/pagamentos/edit/<int:item_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_edit(item_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        pagamento_data_inicio = request.form['pagamento_data_inicio'].strip()
        pagamento_data_fim = request.form['pagamento_data_fim'].strip()
        caixa = request.form['caixa'].strip()

        if not all([pagamento_data_inicio, pagamento_data_fim, caixa]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            cursor.execute("UPDATE contas_a_pagar_pagamentos SET pagamento_data_inicio = ?, pagamento_data_fim = ?, caixa = ? WHERE id = ?",
                           (pagamento_data_inicio, pagamento_data_fim, caixa, item_id))
            db.commit()
            flash('Pagamento atualizado com sucesso!', 'success')
            return redirect(url_for('contas_a_pagar_dashboard'))

    cursor.execute("SELECT * FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if item is None:
        flash('Pagamento não encontrado.', 'danger')
        return redirect(url_for('contas_a_pagar_dashboard'))
    return render_template('contas_a_pagar/contas_a_pagar_pagamentos_edit.html', item=item)

@app.route('/contas_a_pagar/pagamentos/delete/<int:item_id>', methods=['POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_delete(item_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,))
    db.commit()
    flash('Pagamento excluído com sucesso!', 'success')
    return redirect(url_for('contas_a_pagar_dashboard'))


# --- Rotas Contas a Pagar - Documentos Diversos ---
@app.route('/contas_a_pagar/documentos_diversos', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def documentos_diversos_dashboard():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        numero_caixa = request.form['numero_caixa'].strip()

        if not numero_caixa:
            flash('O campo Número da Caixa é obrigatório!', 'danger')
        else:
            try:
                cursor.execute("INSERT INTO contas_a_pagar_diversos (numero_caixa) VALUES (?)", (numero_caixa,))
                db.commit()
                flash('Documento diverso adicionado com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao adicionar documento diverso: {e}', 'danger')

    cursor.execute("SELECT * FROM contas_a_pagar_diversos ORDER BY numero_caixa")
    documentos_diversos = cursor.fetchall()
    
    return render_template('contas_a_pagar/documentos_diversos_dashboard.html', documentos_diversos=documentos_diversos)

@app.route('/contas_a_pagar/documentos_diversos/edit/<int:item_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_edit(item_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        numero_caixa = request.form['numero_caixa'].strip()

        if not numero_caixa:
            flash('O campo Número da Caixa é obrigatório!', 'danger')
        else:
            cursor.execute("UPDATE contas_a_pagar_diversos SET numero_caixa = ? WHERE id = ?",
                           (numero_caixa, item_id))
            db.commit()
            flash('Documento diverso atualizado com sucesso!', 'success')
            return redirect(url_for('documentos_diversos_dashboard'))

    cursor.execute("SELECT * FROM contas_a_pagar_diversos WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if item is None:
        flash('Documento diverso não encontrado.', 'danger')
        return redirect(url_for('documentos_diversos_dashboard'))
    return render_template('contas_a_pagar/documentos_diversos_edit.html', item=item)

@app.route('/contas_a_pagar/documentos_diversos/delete/<int:item_id>', methods=['POST'])
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_delete(item_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM contas_a_pagar_diversos WHERE id = ?", (item_id,))
    db.commit()
    flash('Documento diverso excluído com sucesso!', 'success')
    return redirect(url_for('documentos_diversos_dashboard'))


# --- Rotas Cobrança ---
@app.route('/cobranca/dashboard', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_dashboard():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        ficha_acerto = request.form['ficha_acerto'].strip()
        caixa = request.form['caixa'].strip()
        range_cliente_inicio = request.form['range_cliente_inicio'].strip()
        range_cliente_fim = request.form['range_cliente_fim'].strip()

        if not all([ficha_acerto, caixa, range_cliente_inicio, range_cliente_fim]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            try:
                range_inicio_int = int(range_cliente_inicio)
                range_fim_int = int(range_cliente_fim)

                cursor.execute("INSERT INTO cobranca_fichas_acerto (ficha_acerto, caixa, range_cliente_inicio, range_cliente_fim) VALUES (?, ?, ?, ?)",
                               (ficha_acerto, caixa, range_inicio_int, range_fim_int))
                db.commit()
                flash('Ficha de Acerto adicionada com sucesso!', 'success')
            except ValueError:
                flash('Os campos "De X" e "Até Y" devem ser números válidos.', 'danger')
            except Exception as e:
                flash(f'Erro ao adicionar Ficha de Acerto: {e}', 'danger')
    
    cursor.execute("SELECT * FROM cobranca_fichas_acerto ORDER BY ficha_acerto")
    fichas_acerto = cursor.fetchall()

    return render_template('cobranca/cobranca_dashboard.html', fichas_acerto=fichas_acerto)

@app.route('/cobranca/fichas_acerto/edit/<int:item_id>', methods=['GET', 'POST'])
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_edit(item_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        ficha_acerto = request.form['ficha_acerto'].strip()
        caixa = request.form['caixa'].strip()
        range_cliente_inicio = request.form['range_cliente_inicio'].strip()
        range_cliente_fim = request.form['range_cliente_fim'].strip()

        if not all([ficha_acerto, caixa, range_cliente_inicio, range_cliente_fim]):
            flash('Todos os campos são obrigatórios!', 'danger')
        else:
            try:
                range_inicio_int = int(range_cliente_inicio)
                range_fim_int = int(range_cliente_fim)
                cursor.execute("UPDATE cobranca_fichas_acerto SET ficha_acerto = ?, caixa = ?, range_cliente_inicio = ?, range_cliente_fim = ? WHERE id = ?",
                               (ficha_acerto, caixa, range_inicio_int, range_fim_int, item_id))
                db.commit()
                flash('Ficha de Acerto atualizada com sucesso!', 'success')
                return redirect(url_for('cobranca_dashboard'))
            except ValueError:
                flash('Os campos "De X" e "Até Y" devem ser números válidos.', 'danger')
            except Exception as e:
                flash(f'Erro ao atualizar Ficha de Acerto: {e}', 'danger')

    cursor.execute("SELECT * FROM cobranca_fichas_acerto WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if item is None:
        flash('Ficha de Acerto não encontrada.', 'danger')
        return redirect(url_for('cobranca_dashboard'))
    return render_template('cobranca/cobranca_fichas_acerto_edit.html', item=item)


@app.route('/cobranca/fichas_acerto/delete/<int:item_id>', methods=['POST'])
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_delete(item_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM cobranca_fichas_acerto WHERE id = ?", (item_id,))
    db.commit()
    flash('Ficha de Acerto excluída com sucesso!', 'success')
    return redirect(url_for('cobranca_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)