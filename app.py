from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, Response
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_app, get_db
from datetime import datetime
import json
import io
import csv

app = Flask(__name__)
app.secret_key = '09164Duque!Paprika'
PER_PAGE = 20  # Itens por página para paginação

app.jinja_env.add_extension('jinja2.ext.do')

# --- Filtros Personalizados para Templates ---
@app.template_filter('datetime')
def format_datetime(value, fmt='%d/%m/%Y %H:%M:%S'):
    """Formata uma string de data/hora para o formato brasileiro."""
    if value is None:
        return ""
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f').strftime(fmt)
    except ValueError:
        try:
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').strftime(fmt)
        except ValueError:
            return value

@app.template_filter('prettyjson')
def pretty_json_filter(value):
    """Formata uma string JSON para uma exibição HTML legível."""
    if not value or value == 'null':
        return 'N/A'
    try:
        data = json.loads(value)
        # Formata como uma lista de chave-valor
        html = "<ul>"
        for key, val in data.items():
            if key != 'password': # Não exibir senhas
                html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {val}</li>"
        html += "</ul>"
        return html
    except (json.JSONDecodeError, AttributeError):
        return value

# Inicializa o banco de dados com o app Flask
init_app(app)


# --- Funções Auxiliares e de Auditoria ---
def is_ajax_request():
    """Verifica se a requisição é do tipo AJAX."""
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def log_action(action, target_type=None, target_id=None, target_name=None, dados_antigos=None, dados_novos=None):
    db = get_db()
    dados_antigos_str = json.dumps(dados_antigos, ensure_ascii=False) if isinstance(dados_antigos, dict) else dados_antigos
    dados_novos_str = json.dumps(dados_novos, ensure_ascii=False) if isinstance(dados_novos, dict) else dados_novos
    db.execute(
        "INSERT INTO audit_log (user_id, username, action, target_type, target_id, target_name, dados_antigos, dados_novos) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (session.get('user_id'), session.get('username'), action, target_type, target_id, target_name, dados_antigos_str, dados_novos_str)
    )
    db.commit()


# --- Decoradores de Permissão ---
def login_required(f):
    """Garante que o usuário esteja logado para acessar a rota."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            if is_ajax_request():
                return jsonify({'status': 'error', 'message': 'Sessão expirada. Faça login novamente.'}), 401
            flash('Você precisa fazer login para acessar esta página.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(allowed_roles):
    """Garante que o usuário tenha uma das funções permitidas."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in') or session.get('role') not in allowed_roles:
                if is_ajax_request():
                    return jsonify({'status': 'error', 'message': 'Você não tem permissão para esta ação.'}), 403
                log_action('access_denied', target_name=request.path)
                flash('Você não tem permissão para acessar esta página.', 'danger')
                return redirect(url_for('admin_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Rotas Principais e de Busca ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def admin_dashboard():
    role_map = {
        'super_admin': 'super_admin_dashboard',
        'admin_patrimonio': 'patrimonio_dashboard',
        'admin_rh': 'rh_dashboard',
        'admin_contas_a_pagar': 'contas_a_pagar_dashboard',
        'admin_cobranca': 'cobranca_dashboard'
    }
    dashboard_route = role_map.get(session.get('role'), 'index')
    return redirect(url_for(dashboard_route))


@app.route('/search', methods=['GET'])
def search():
    page = request.args.get('page', 1, type=int)
    query = request.args.get('query', '').strip()
    search_by = request.args.get('search_by', 'codigo_cliente')
    all_results = []

    if query:
        db = get_db()
        query_term = '%' + query + '%'

        if search_by == 'codigo_cliente':
            all_results = db.execute("SELECT * FROM patrimonios WHERE codigo_cliente LIKE ?", (query_term,)).fetchall()
        elif search_by == 'nome_cliente':
            all_results = db.execute("SELECT * FROM patrimonios WHERE nome_cliente LIKE ?", (query_term,)).fetchall()
        elif search_by == 'patrimonio_especifico':
            items = db.execute("SELECT * FROM patrimonios").fetchall()
            all_results = [row for row in items if any(query.lower() in p.strip().lower() for p in row['patrimonios'].split('/'))]
        elif search_by == 'caixa_cobranca_range':
            try:
                cliente_num = int(query)
                all_results = db.execute("SELECT * FROM cobranca_fichas_acerto WHERE ? BETWEEN range_cliente_inicio AND range_cliente_fim", (cliente_num,)).fetchall()
            except ValueError:
                flash('Para pesquisa por "Caixa Cobrança", digite um número de cliente válido.', 'danger')
        elif search_by == 'numero_caixa':
            pat_res = db.execute("SELECT p.numero_caixa, p.patrimonios, 'Patrimônio' as type, s.name as store_name FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id WHERE p.numero_caixa LIKE ?", (query_term,)).fetchall()
            for row in pat_res:
                all_results.append({'type': row['type'], 'caixa': row['numero_caixa'], 'description': row['patrimonios'], 'store_name': row['store_name']})
            pag_res = db.execute("SELECT cap.caixa, cap.pagamento_data_inicio, cap.pagamento_data_fim, 'Pagamento' as type, s.name as store_name FROM contas_a_pagar_pagamentos cap LEFT JOIN stores s ON cap.store_id = s.id WHERE cap.caixa LIKE ?", (query_term,)).fetchall()
            for row in pag_res:
                all_results.append({'type': row['type'], 'caixa': row['caixa'], 'description': f"Período de {row['pagamento_data_inicio']} a {row['pagamento_data_fim']}", 'store_name': row['store_name']})
            div_res = db.execute("SELECT cad.numero_caixa, 'Documento Diverso' as type, s.name as store_name FROM contas_a_pagar_diversos cad LEFT JOIN stores s ON cad.store_id = s.id WHERE cad.numero_caixa LIKE ?", (query_term,)).fetchall()
            for row in div_res:
                all_results.append({'type': row['type'], 'caixa': row['numero_caixa'], 'description': 'N/A', 'store_name': row['store_name']})
            cob_res = db.execute("SELECT cfa.caixa, cfa.range_cliente_inicio, cfa.range_cliente_fim, 'Cobrança' as type, s.name as store_name FROM cobranca_fichas_acerto cfa LEFT JOIN stores s ON cfa.store_id = s.id WHERE cfa.caixa LIKE ?", (query_term,)).fetchall()
            for row in cob_res:
                all_results.append({'type': row['type'], 'caixa': row['caixa'], 'description': f"{row['range_cliente_inicio']} - {row['range_cliente_fim']}", 'store_name': row['store_name']})

    # Implementa a paginação na lista de resultados
    total_items = len(all_results)
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE
    paginated_results = all_results[offset : offset + PER_PAGE]

    return render_template('search_results.html', 
                           results=paginated_results, 
                           query=query, 
                           search_by=search_by,
                           page=page,
                           total_pages=total_pages)


# --- Rotas de Autenticação e Perfil ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT u.*, s.name as store_name FROM users u LEFT JOIN stores s ON u.store_id = s.id WHERE u.username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['store_id'] = user['store_id']
            session['store_name'] = user['store_name']
            log_action('login_success')
            flash(f'Login bem-sucedido! Bem-vindo, {user["username"]}.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            log_action('login_failed', target_name=username)
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    log_action('logout')
    session.clear()
    flash('Você foi desconectado com segurança.', 'info')
    return redirect(url_for('index'))


@app.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

        if not user or not check_password_hash(user['password'], current_password):
            flash('Sua senha atual está incorreta.', 'danger')
        elif len(new_password) < 6:
            flash('A nova senha deve ter pelo menos 6 caracteres.', 'warning')
        elif new_password != confirm_password:
            flash('A nova senha e a confirmação não correspondem.', 'danger')
        else:
            hashed_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session['user_id']))
            db.commit()
            log_action('change_password_self')
            flash('Sua senha foi alterada com sucesso!', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('profile/change_password.html')


# --- Rotas de Super Admin ---
@app.route('/super_admin/dashboard')
@login_required
@role_required(['super_admin'])
def super_admin_dashboard():
    return render_template('super_admin/super_admin_dashboard.html')


@app.route('/super_admin/audit_log')
@login_required
@role_required(['super_admin'])
def audit_log():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    user_search = request.args.get('user_search', '').strip()
    action_filter = request.args.get('action_filter', '')
    
    base_query = "FROM audit_log WHERE 1=1"
    params = []
    
    if user_search:
        base_query += " AND username LIKE ?"
        params.append(f"%{user_search}%")
    if action_filter:
        base_query += " AND action = ?"
        params.append(action_filter)
        
    total_items = db.execute(f"SELECT COUNT(id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE

    logs = db.execute(f"SELECT * {base_query} ORDER BY timestamp DESC LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()
    distinct_actions = db.execute("SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()

    return render_template('super_admin/audit_log.html', 
                           logs=logs, 
                           distinct_actions=distinct_actions,
                           current_filters={'user': user_search, 'action': action_filter},
                           page=page,
                           total_pages=total_pages)

@app.route('/super_admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin'])
def user_edit(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('user_management'))

    if request.method == 'POST':
        dados_antigos = dict(user)
        dados_antigos.pop('password', None) # Remove a senha dos dados antigos

        # Pega os novos dados do formulário
        role = request.form['role']
        store_id = request.form.get('store_id') or None
        can_add_users = 1 if 'can_add_users' in request.form else 0
        new_password = request.form['new_password'].strip()

        db.execute("UPDATE users SET role = ?, store_id = ?, can_add_users = ? WHERE id = ?",
                   (role, store_id, can_add_users, user_id))
        
        dados_novos = {'role': role, 'store_id': store_id, 'can_add_users': can_add_users}

        if new_password:
            if len(new_password) < 6:
                flash('A nova senha deve ter pelo menos 6 caracteres.', 'warning')
                return redirect(url_for('user_edit', user_id=user_id))
            hashed_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            dados_novos['password'] = '******' # Log que a senha foi alterada sem mostrar o valor
        
        db.commit()
        log_action('edit_user', target_id=user_id, target_name=user['username'], dados_antigos=dados_antigos, dados_novos=dados_novos)
        flash(f'Usuário {user["username"]} atualizado com sucesso!', 'success')
        return redirect(url_for('user_management'))

    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    return render_template('super_admin/user_edit.html', user=user, stores=stores)

@app.route('/super_admin/users', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin'])
def user_management():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        store_id = request.form.get('store_id') or None
        can_add_users = 1 if 'can_add_users' in request.form else 0

        if not all([username, password, role]):
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Usuário, senha e função são obrigatórios!'}), 400
            flash('Usuário, senha e função são obrigatórios!', 'danger')
        else:
            try:
                hashed_password = generate_password_hash(password)
                cursor = db.cursor()
                cursor.execute("INSERT INTO users (username, password, role, can_add_users, store_id) VALUES (?, ?, ?, ?, ?)",
                               (username, hashed_password, role, can_add_users, store_id))
                new_user_id = cursor.lastrowid
                db.commit()
                log_action('create_user', target_id=new_user_id, target_name=username)

                if is_ajax_request():
                    new_user = db.execute("SELECT u.*, s.name as store_name FROM users u LEFT JOIN stores s ON u.store_id = s.id WHERE u.id = ?", (new_user_id,)).fetchone()
                    return jsonify({'status': 'success', 'message': f'Usuário {username} criado!', 'item': dict(new_user), 'page_type': 'user_management'})
                flash(f'Usuário {username} criado com sucesso!', 'success')
            except sqlite3.IntegrityError:
                if is_ajax_request(): return jsonify({'status': 'error', 'message': f'Erro: Usuário "{username}" já existe.'}), 409
                flash(f'Erro: Usuário "{username}" já existe.', 'danger')
        return redirect(url_for('user_management'))

    params = []
    where_clauses = []
    if search_query:
        search_term = f"%{search_query}%"
        search_clauses = ["u.username LIKE ?", "u.role LIKE ?", "s.name LIKE ?"]
        where_clauses.append(f"({' OR '.join(search_clauses)})")
        params.extend([search_term] * len(search_clauses))
    
    base_query = "FROM users u LEFT JOIN stores s ON u.store_id = s.id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    total_items = db.execute(f"SELECT COUNT(u.id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE

    users = db.execute(f"SELECT u.*, s.name as store_name {base_query} ORDER BY u.username LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()
    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall()
    
    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': [dict(r) for r in users],
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, search=search_query, request=request),
            'page_type': 'user_management'
        })
        
    return render_template('super_admin/user_management.html', users=users, stores=stores, page=page, total_pages=total_pages, search=search_query)


@app.route('/super_admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['super_admin'])
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user['role'] == 'super_admin':
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Não é possível excluir um Super Admin.'}), 403
        flash('Não é possível excluir um Super Admin.', 'danger')
    elif user:
        log_action('delete_user', target_id=user_id, target_name=user['username'], dados_antigos=dict(user))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        if is_ajax_request(): return jsonify({'status': 'success', 'message': 'Usuário excluído!', 'itemId': user_id})
        flash('Usuário excluído com sucesso!', 'success')
    else:
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404
        flash('Usuário não encontrado.', 'danger')
    return redirect(url_for('user_management'))


@app.route('/super_admin/stores', methods=['GET', 'POST'], endpoint='manage_stores')
@login_required
@role_required(['super_admin'])
def manage_stores():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()

    if request.method == 'POST':
        store_name = request.form.get('name', '').strip()
        selected_departments = request.form.getlist('departments')
        if not store_name or not selected_departments:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Nome e pelo menos um departamento são obrigatórios.'}), 400
            flash('O nome da EMPRESA e pelo menos um departamento são obrigatórios.', 'danger')
        else:
            try:
                cursor = db.cursor()
                cursor.execute("INSERT INTO stores (name) VALUES (?)", (store_name,))
                store_id = cursor.lastrowid
                for dept_role in selected_departments:
                    cursor.execute("INSERT INTO store_departments (store_id, department_role) VALUES (?, ?)", (store_id, dept_role))
                db.commit()
                log_action('create_store', target_id=store_id, target_name=store_name, dados_novos={'name': store_name, 'departments': selected_departments})
                
                if is_ajax_request():
                    new_store_q = "SELECT s.id, s.name, GROUP_CONCAT(sd.department_role, ', ') as departments FROM stores s LEFT JOIN store_departments sd ON s.id = sd.store_id WHERE s.id = ? GROUP BY s.id"
                    new_store = db.execute(new_store_q, (store_id,)).fetchone()
                    return jsonify({'status': 'success', 'message': f'Empresa "{store_name}" criada!', 'item': dict(new_store), 'page_type': 'manage_stores'})
                flash(f'EMPRESA "{store_name}" criada com sucesso!', 'success')

            except sqlite3.IntegrityError:
                if is_ajax_request(): return jsonify({'status': 'error', 'message': f'Erro: A empresa "{store_name}" já existe.'}), 409
                flash(f'Erro: A EMPRESA "{store_name}" já existe.', 'danger')
        return redirect(url_for('manage_stores'))

    params = []
    where_clauses = []
    if search_query:
        search_term = f"%{search_query}%"
        search_clauses = ["s.name LIKE ?", "sd.department_role LIKE ?"]
        where_clauses.append(f"({' OR '.join(search_clauses)})")
        params.extend([search_term] * len(search_clauses))

    base_query = "FROM stores s LEFT JOIN store_departments sd ON s.id = sd.store_id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)
    
    # Use subquery to count distinct stores
    count_query = f"SELECT COUNT(DISTINCT s.id) FROM stores s LEFT JOIN store_departments sd ON s.id = sd.store_id"
    if where_clauses:
        count_query += " WHERE " + " AND ".join(where_clauses)

    total_items = db.execute(count_query, params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE

    query = f"SELECT s.id, s.name, GROUP_CONCAT(sd.department_role, ', ') as departments {base_query} GROUP BY s.id, s.name ORDER BY s.name LIMIT ? OFFSET ?"
    stores_data = db.execute(query, params + [PER_PAGE, offset]).fetchall()
    
    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': [dict(r) for r in stores_data],
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, search=search_query, request=request),
            'page_type': 'manage_stores'
        })

    available_departments = ['admin_rh', 'admin_patrimonio', 'admin_contas_a_pagar', 'admin_cobranca']
    return render_template('super_admin/manage_stores.html', stores=stores_data, available_departments=available_departments, page=page, total_pages=total_pages, search=search_query)


@app.route('/super_admin/stores/delete/<int:store_id>', methods=['POST'])
@login_required
@role_required(['super_admin'])
def delete_store(store_id):
    db = get_db()
    store = db.execute("SELECT * FROM stores WHERE id = ?", (store_id,)).fetchone()
    if store:
        db.execute("UPDATE users SET store_id = NULL WHERE store_id = ?", (store_id,))
        db.execute("DELETE FROM stores WHERE id = ?", (store_id,))
        db.commit()
        log_action('delete_store', target_id=store_id, target_name=store['name'], dados_antigos=dict(store))
        if is_ajax_request():
            return jsonify({'status': 'success', 'message': 'Empresa excluída!', 'itemId': store_id})
        flash('EMPRESA excluída com sucesso!', 'success')
    else:
        if is_ajax_request():
            return jsonify({'status': 'error', 'message': 'Empresa não encontrada.'}), 404
        flash('EMPRESA não encontrada.', 'danger')
    return redirect(url_for('manage_stores'))


# --- Rotas de Patrimônio ---
@app.route('/patrimonio/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_dashboard():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    db = get_db()

    if request.method == 'POST':
        store_id = session.get('store_id') if session['role'] != 'super_admin' else request.form.get('store_id')
        if session['role'] == 'super_admin' and not store_id:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Como Super Admin, você deve selecionar uma EMPRESA.'}), 400
            flash('Como Super Admin, você deve selecionar uma EMPRESA.', 'danger')
            return redirect(url_for('patrimonio_dashboard'))
        
        dados_novos = {'codigo_cliente': request.form['codigo_cliente'], 'nome_cliente': request.form['nome_cliente'], 'patrimonios': request.form['patrimonios'], 'numero_caixa': request.form['numero_caixa'], 'store_id': store_id}
        cursor = db.cursor()
        cursor.execute("INSERT INTO patrimonios (codigo_cliente, nome_cliente, patrimonios, numero_caixa, store_id) VALUES (?, ?, ?, ?, ?)", list(dados_novos.values()))
        new_id = cursor.lastrowid
        db.commit()
        log_action('add_patrimonio', target_id=new_id, target_name=dados_novos['codigo_cliente'], dados_novos=dados_novos)

        if is_ajax_request():
            new_item = db.execute("SELECT p.*, s.name as store_name FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id WHERE p.id = ?", (new_id,)).fetchone()
            return jsonify({'status': 'success', 'message': 'Patrimônio adicionado!', 'item': dict(new_item), 'page_type': 'patrimonio'})
        flash('Patrimônio adicionado com sucesso!', 'success')
        return redirect(url_for('patrimonio_dashboard'))

    params = []
    where_clauses = []

    if session['role'] != 'super_admin':
        where_clauses.append("p.store_id = ?")
        params.append(session.get('store_id'))

    if search_query:
        search_term = f"%{search_query}%"
        search_clauses_list = ["p.codigo_cliente LIKE ?", "p.nome_cliente LIKE ?", "p.patrimonios LIKE ?", "p.numero_caixa LIKE ?"]
        if session['role'] == 'super_admin':
            search_clauses_list.append("s.name LIKE ?")
        
        where_clauses.append(f"({' OR '.join(search_clauses_list)})")
        params.extend([search_term] * len(search_clauses_list))

    base_query = "FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    total_items = db.execute(f"SELECT COUNT(p.id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE
    items = db.execute(f"SELECT p.*, s.name as store_name {base_query} ORDER BY p.id DESC LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()

    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': [dict(r) for r in items],
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, search=search_query, request=request),
            'page_type': 'patrimonio'
        })

    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall() if session['role'] == 'super_admin' else []
    return render_template('patrimonio/patrimonio_dashboard.html', patrimonios=items, stores=stores, page=page, total_pages=total_pages, search=search_query)


@app.route('/patrimonio/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM patrimonios WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Patrimônio não encontrado ou sem permissão.'}), 403
        flash('Patrimônio não encontrado ou sem permissão para excluir.', 'danger')
    else:
        log_action('delete_patrimonio', target_id=item_id, target_name=item['codigo_cliente'], dados_antigos=dict(item))
        db.execute("DELETE FROM patrimonios WHERE id = ?", (item_id,))
        db.commit()
        if is_ajax_request(): return jsonify({'status': 'success', 'message': 'Patrimônio excluído!', 'itemId': item_id})
        flash('Patrimônio excluído com sucesso!', 'success')
    return redirect(url_for('patrimonio_dashboard'))


@app.route('/patrimonio/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM patrimonios WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Patrimônio não encontrado ou sem permissão.', 'danger')
        return redirect(url_for('patrimonio_dashboard'))

    if request.method == 'POST':
        dados_antigos = dict(item)
        dados_novos = {'codigo_cliente': request.form['codigo_cliente'], 'nome_cliente': request.form['nome_cliente'], 'patrimonios': request.form['patrimonios'], 'numero_caixa': request.form['numero_caixa']}
        db.execute("UPDATE patrimonios SET codigo_cliente = ?, nome_cliente = ?, patrimonios = ?, numero_caixa = ? WHERE id = ?",
                   (dados_novos['codigo_cliente'], dados_novos['nome_cliente'], dados_novos['patrimonios'], dados_novos['numero_caixa'], item_id))
        db.commit()
        log_action('edit_patrimonio', target_id=item_id, target_name=dados_novos['codigo_cliente'], dados_antigos=dados_antigos, dados_novos=dados_novos)
        flash('Patrimônio atualizado com sucesso!', 'success')
        return redirect(url_for('patrimonio_dashboard'))
    return render_template('patrimonio/patrimonio_edit.html', item=item)


@app.route('/patrimonio/export_csv')
@login_required
@role_required(['super_admin', 'admin_patrimonio'])
def patrimonio_export_csv():
    db = get_db()
    query = "SELECT p.id, p.codigo_cliente, p.nome_cliente, p.patrimonios, p.numero_caixa, s.name as store_name FROM patrimonios p LEFT JOIN stores s ON p.store_id = s.id"
    params = []
    if session['role'] != 'super_admin':
        query += " WHERE p.store_id = ?"
        params.append(session.get('store_id'))
    
    items = db.execute(query, params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Código Cliente', 'Nome Cliente', 'Patrimônios', 'Nº Caixa', 'Empresa'])
    for item in items:
        writer.writerow([item['id'], item['codigo_cliente'], item['nome_cliente'], item['patrimonios'], item['numero_caixa'], item['store_name']])
    
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=patrimonios.csv"})


# --- Rotas RH ---
@app.route('/rh/dashboard')
@login_required
@role_required(['super_admin', 'admin_rh'])
def rh_dashboard():
    return render_template('rh/rh_dashboard.html')


# --- Rotas Contas a Pagar (Pagamentos) ---
@app.route('/contas_a_pagar/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_dashboard():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    db = get_db()

    if request.method == 'POST':
        store_id = session.get('store_id') if session['role'] != 'super_admin' else request.form.get('store_id')
        if session['role'] == 'super_admin' and not store_id:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Como Super Admin, você deve selecionar uma EMPRESA.'}), 400
            flash('Como Super Admin, você deve selecionar uma EMPRESA.', 'danger')
            return redirect(url_for('contas_a_pagar_dashboard'))
        
        dados_novos = {'pagamento_data_inicio': request.form['pagamento_data_inicio'], 'pagamento_data_fim': request.form['pagamento_data_fim'], 'caixa': request.form['caixa'], 'store_id': store_id}
        cursor = db.cursor()
        cursor.execute("INSERT INTO contas_a_pagar_pagamentos (pagamento_data_inicio, pagamento_data_fim, caixa, store_id) VALUES (?, ?, ?, ?)", list(dados_novos.values()))
        new_id = cursor.lastrowid
        db.commit()
        log_action('add_pagamento', target_id=new_id, target_name=f"Caixa {dados_novos['caixa']}", dados_novos=dados_novos)

        if is_ajax_request():
            new_item = db.execute("SELECT p.*, s.name as store_name FROM contas_a_pagar_pagamentos p LEFT JOIN stores s ON p.store_id = s.id WHERE p.id = ?", (new_id,)).fetchone()
            item_dict = dict(new_item)
            item_dict['pagamento_data_inicio'] = datetime.strptime(item_dict['pagamento_data_inicio'], '%Y-%m-%d').strftime('%d/%m/%Y')
            item_dict['pagamento_data_fim'] = datetime.strptime(item_dict['pagamento_data_fim'], '%Y-%m-%d').strftime('%d/%m/%Y')
            return jsonify({'status': 'success', 'message': 'Pagamento adicionado!', 'item': item_dict, 'page_type': 'contas_a_pagar_pagamentos'})
        flash('Pagamento adicionado com sucesso!', 'success')
        return redirect(url_for('contas_a_pagar_dashboard'))

    params = []
    where_clauses = []

    if session['role'] != 'super_admin':
        where_clauses.append("p.store_id = ?")
        params.append(session.get('store_id'))

    if search_query:
        search_term = f"%{search_query}%"
        search_clauses_list = ["p.caixa LIKE ?", "p.pagamento_data_inicio LIKE ?", "p.pagamento_data_fim LIKE ?"]
        if session['role'] == 'super_admin':
            search_clauses_list.append("s.name LIKE ?")
        
        where_clauses.append(f"({' OR '.join(search_clauses_list)})")
        params.extend([search_term] * len(search_clauses_list))

    base_query = "FROM contas_a_pagar_pagamentos p LEFT JOIN stores s ON p.store_id = s.id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)


    total_items = db.execute(f"SELECT COUNT(p.id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE
    items = db.execute(f"SELECT p.*, s.name as store_name {base_query} ORDER BY p.id DESC LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()
    
    items_formatted = []
    for item in items:
        item_dict = dict(item)
        try:
            item_dict['pagamento_data_inicio'] = datetime.strptime(item_dict['pagamento_data_inicio'], '%Y-%m-%d').strftime('%d/%m/%Y')
            item_dict['pagamento_data_fim'] = datetime.strptime(item_dict['pagamento_data_fim'], '%Y-%m-%d').strftime('%d/%m/%Y')
        except (ValueError, TypeError): pass
        items_formatted.append(item_dict)

    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': items_formatted,
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, search=search_query, request=request),
            'page_type': 'contas_a_pagar_pagamentos'
        })

    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall() if session['role'] == 'super_admin' else []
    return render_template('contas_a_pagar/contas_a_pagar_dashboard.html', pagamentos=items_formatted, stores=stores, page=page, total_pages=total_pages, search=search_query)


@app.route('/contas_a_pagar/pagamentos/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Registro não encontrado ou sem permissão.'}), 403
        flash('Registro não encontrado ou sem permissão.', 'danger')
    else:
        log_action('delete_pagamento', target_id=item_id, target_name=f"Caixa {item['caixa']}", dados_antigos=dict(item))
        db.execute("DELETE FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,))
        db.commit()
        if is_ajax_request(): return jsonify({'status': 'success', 'message': 'Registro excluído!', 'itemId': item_id})
        flash('Registro excluído com sucesso!', 'success')
    return redirect(url_for('contas_a_pagar_dashboard'))


@app.route('/contas_a_pagar/pagamentos/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_pagamentos_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_pagamentos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Registro não encontrado ou sem permissão.', 'danger')
        return redirect(url_for('contas_a_pagar_dashboard'))

    if request.method == 'POST':
        dados_antigos = dict(item)
        dados_novos = {'pagamento_data_inicio': request.form['pagamento_data_inicio'], 'pagamento_data_fim': request.form['pagamento_data_fim'], 'caixa': request.form['caixa']}
        db.execute("UPDATE contas_a_pagar_pagamentos SET pagamento_data_inicio = ?, pagamento_data_fim = ?, caixa = ? WHERE id = ?", 
                   (dados_novos['pagamento_data_inicio'], dados_novos['pagamento_data_fim'], dados_novos['caixa'], item_id))
        db.commit()
        log_action('edit_pagamento', target_id=item_id, target_name=f"Caixa {dados_novos['caixa']}", dados_antigos=dados_antigos, dados_novos=dados_novos)
        flash('Registro atualizado com sucesso!', 'success')
        return redirect(url_for('contas_a_pagar_dashboard'))
    return render_template('contas_a_pagar/contas_a_pagar_pagamentos_edit.html', item=item)


# --- Rotas de Cobrança ---
@app.route('/cobranca/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_dashboard():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    db = get_db()

    if request.method == 'POST':
        store_id = session.get('store_id') if session['role'] != 'super_admin' else request.form.get('store_id')
        if session['role'] == 'super_admin' and not store_id:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Como Super Admin, você deve selecionar uma EMPRESA.'}), 400
            flash('Como Super Admin, você deve selecionar uma EMPRESA.', 'danger')
            return redirect(url_for('cobranca_dashboard'))
            
        try:
            pos_cursor = db.execute("SELECT IFNULL(MAX(order_position), 0) + 1 AS next_pos FROM cobranca_fichas_acerto WHERE store_id " + ("= ?" if store_id else "IS NULL"), (store_id,) if store_id else ())
            next_pos = pos_cursor.fetchone()['next_pos']
            dados_novos = {'ficha_acerto': request.form['ficha_acerto'], 'caixa': request.form['caixa'], 'range_cliente_inicio': int(request.form['range_cliente_inicio']), 'range_cliente_fim': int(request.form['range_cliente_fim']), 'store_id': store_id, 'order_position': next_pos}
            cursor = db.cursor()
            cursor.execute("INSERT INTO cobranca_fichas_acerto (ficha_acerto, caixa, range_cliente_inicio, range_cliente_fim, store_id, order_position) VALUES (?, ?, ?, ?, ?, ?)", list(dados_novos.values()))
            new_id = cursor.lastrowid
            db.commit()
            log_action('add_ficha_acerto', target_id=new_id, target_name=f"Ficha {dados_novos['ficha_acerto']}", dados_novos=dados_novos)

            if is_ajax_request():
                new_item = db.execute("SELECT f.*, s.name as store_name FROM cobranca_fichas_acerto f LEFT JOIN stores s ON f.store_id = s.id WHERE f.id = ?", (new_id,)).fetchone()
                return jsonify({'status': 'success', 'message': 'Ficha de Acerto adicionada!', 'item': dict(new_item), 'page_type': 'cobranca'})
            flash('Ficha de Acerto adicionada com sucesso!', 'success')
        except ValueError:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Os campos de range de cliente devem ser números.'}), 400
            flash('Os campos de range de cliente devem ser números.', 'danger')
        return redirect(url_for('cobranca_dashboard'))

    params = []
    where_clauses = []

    if session['role'] != 'super_admin':
        where_clauses.append("f.store_id = ?")
        params.append(session.get('store_id'))

    if search_query:
        search_term = f"%{search_query}%"
        search_clauses_list = ["f.ficha_acerto LIKE ?", "f.caixa LIKE ?", "f.range_cliente_inicio LIKE ?", "f.range_cliente_fim LIKE ?"]
        if session['role'] == 'super_admin':
            search_clauses_list.append("s.name LIKE ?")
        
        where_clauses.append(f"({' OR '.join(search_clauses_list)})")
        params.extend([search_term] * len(search_clauses_list))

    base_query = "FROM cobranca_fichas_acerto f LEFT JOIN stores s ON f.store_id = s.id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)


    total_items = db.execute(f"SELECT COUNT(f.id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE
    items = db.execute(f"SELECT f.*, s.name as store_name {base_query} ORDER BY f.order_position ASC LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()
    
    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': [dict(r) for r in items],
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, search=search_query, request=request),
            'page_type': 'cobranca'
        })
    
    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall() if session['role'] == 'super_admin' else []
    return render_template('cobranca/cobranca_dashboard.html', fichas_acerto=items, stores=stores, page=page, total_pages=total_pages, search=search_query)


@app.route('/cobranca/fichas_acerto/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM cobranca_fichas_acerto WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Ficha de Acerto não encontrada ou sem permissão.'}), 403
        flash('Ficha de Acerto não encontrada ou sem permissão.', 'danger')
    else:
        log_action('delete_ficha_acerto', target_id=item_id, target_name=f"Ficha {item['ficha_acerto']}", dados_antigos=dict(item))
        db.execute("DELETE FROM cobranca_fichas_acerto WHERE id = ?", (item_id,))
        db.commit()
        if is_ajax_request(): return jsonify({'status': 'success', 'message': 'Ficha de Acerto excluída!', 'itemId': item_id})
        flash('Ficha de Acerto excluída com sucesso!', 'success')
    return redirect(url_for('cobranca_dashboard'))


@app.route('/cobranca/fichas_acerto/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM cobranca_fichas_acerto WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Ficha de Acerto não encontrada ou sem permissão.', 'danger')
        return redirect(url_for('cobranca_dashboard'))

    if request.method == 'POST':
        try:
            dados_antigos = dict(item)
            dados_novos = {'ficha_acerto': request.form['ficha_acerto'], 'caixa': request.form['caixa'], 'range_cliente_inicio': int(request.form['range_cliente_inicio']), 'range_cliente_fim': int(request.form['range_cliente_fim'])}
            db.execute("UPDATE cobranca_fichas_acerto SET ficha_acerto = ?, caixa = ?, range_cliente_inicio = ?, range_cliente_fim = ? WHERE id = ?", 
                       (dados_novos['ficha_acerto'], dados_novos['caixa'], dados_novos['range_cliente_inicio'], dados_novos['range_cliente_fim'], item_id))
            db.commit()
            log_action('edit_ficha_acerto', target_id=item_id, target_name=f"Ficha {dados_novos['ficha_acerto']}", dados_antigos=dados_antigos, dados_novos=dados_novos)
            flash('Ficha de Acerto atualizada com sucesso!', 'success')
        except ValueError:
            flash('Os campos de range de cliente devem ser números.', 'danger')
        return redirect(url_for('cobranca_dashboard'))
    return render_template('cobranca/cobranca_fichas_acerto_edit.html', item=item)


@app.route('/cobranca/export_csv')
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_export_csv():
    db = get_db()
    query = "SELECT f.id, f.ficha_acerto, f.caixa, f.range_cliente_inicio, f.range_cliente_fim, s.name as store_name FROM cobranca_fichas_acerto f LEFT JOIN stores s ON f.store_id = s.id"
    params = []
    if session['role'] != 'super_admin':
        query += " WHERE f.store_id = ?"
        params.append(session.get('store_id'))
    
    items = db.execute(query + " ORDER BY f.order_position ASC", params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Ficha de Acerto', 'Caixa', 'Range Cliente Início', 'Range Cliente Fim', 'Empresa'])
    for item in items:
        writer.writerow([item['id'], item['ficha_acerto'], item['caixa'], item['range_cliente_inicio'], item['range_cliente_fim'], item['store_name']])
    
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=cobranca_fichas_acerto.csv"})


# --- Rotas Contas a Pagar (Documentos Diversos) ---
@app.route('/contas_a_pagar/documentos_diversos', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def documentos_diversos_dashboard():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    db = get_db()

    if request.method == 'POST':
        store_id = session.get('store_id') if session['role'] != 'super_admin' else request.form.get('store_id')
        if session['role'] == 'super_admin' and not store_id:
            if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Como Super Admin, você deve selecionar uma EMPRESA.'}), 400
            flash('Como Super Admin, você deve selecionar uma EMPRESA.', 'danger')
            return redirect(url_for('documentos_diversos_dashboard'))

        dados_novos = {'numero_caixa': request.form['numero_caixa'], 'store_id': store_id}
        cursor = db.cursor()
        cursor.execute("INSERT INTO contas_a_pagar_diversos (numero_caixa, store_id) VALUES (?, ?)", list(dados_novos.values()))
        new_id = cursor.lastrowid
        db.commit()
        log_action('add_documento_diverso', target_id=new_id, target_name=f"Caixa {dados_novos['numero_caixa']}", dados_novos=dados_novos)

        if is_ajax_request():
            new_item = db.execute("SELECT d.*, s.name as store_name FROM contas_a_pagar_diversos d LEFT JOIN stores s ON d.store_id = s.id WHERE d.id = ?", (new_id,)).fetchone()
            return jsonify({'status': 'success', 'message': 'Documento adicionado!', 'item': dict(new_item), 'page_type': 'contas_a_pagar_diversos'})
        flash('Documento diverso adicionado com sucesso!', 'success')
        return redirect(url_for('documentos_diversos_dashboard'))

    params = []
    where_clauses = []

    if session['role'] != 'super_admin':
        where_clauses.append("d.store_id = ?")
        params.append(session.get('store_id'))

    if search_query:
        search_term = f"%{search_query}%"
        search_clauses_list = ["d.numero_caixa LIKE ?"]
        if session['role'] == 'super_admin':
            search_clauses_list.append("s.name LIKE ?")
        
        where_clauses.append(f"({' OR '.join(search_clauses_list)})")
        params.extend([search_term] * len(search_clauses_list))

    base_query = "FROM contas_a_pagar_diversos d LEFT JOIN stores s ON d.store_id = s.id"
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)

    total_items = db.execute(f"SELECT COUNT(d.id) {base_query}", params).fetchone()[0]
    total_pages = (total_items + PER_PAGE - 1) // PER_PAGE if total_items > 0 else 1
    offset = (page - 1) * PER_PAGE
    items = db.execute(f"SELECT d.*, s.name as store_name {base_query} ORDER BY d.id DESC LIMIT ? OFFSET ?", params + [PER_PAGE, offset]).fetchall()
    
    if is_ajax_request() and request.method == 'GET':
        return jsonify({
            'items': [dict(r) for r in items],
            'pagination_html': render_template('_pagination.html', page=page, total_pages=total_pages, request=request, search=search_query),
            'page_type': 'contas_a_pagar_diversos'
        })
    
    stores = db.execute("SELECT id, name FROM stores ORDER BY name").fetchall() if session['role'] == 'super_admin' else []
    return render_template('contas_a_pagar/documentos_diversos_dashboard.html', documentos_diversos=items, stores=stores, page=page, total_pages=total_pages, search=search_query)


@app.route('/contas_a_pagar/documentos_diversos/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_diversos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        if is_ajax_request(): return jsonify({'status': 'error', 'message': 'Documento não encontrado ou sem permissão.'}), 403
        flash('Documento não encontrado ou sem permissão.', 'danger')
    else:
        log_action('delete_documento_diverso', target_id=item_id, target_name=f"Caixa {item['numero_caixa']}", dados_antigos=dict(item))
        db.execute("DELETE FROM contas_a_pagar_diversos WHERE id = ?", (item_id,))
        db.commit()
        if is_ajax_request(): return jsonify({'status': 'success', 'message': 'Documento excluído!', 'itemId': item_id})
        flash('Documento excluído com sucesso!', 'success')
    return redirect(url_for('documentos_diversos_dashboard'))


@app.route('/contas_a_pagar/documentos_diversos/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@role_required(['super_admin', 'admin_contas_a_pagar'])
def contas_a_pagar_diversos_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM contas_a_pagar_diversos WHERE id = ?", (item_id,)).fetchone()
    if not item or (session['role'] != 'super_admin' and item['store_id'] != session.get('store_id')):
        flash('Documento não encontrado ou sem permissão.', 'danger')
        return redirect(url_for('documentos_diversos_dashboard'))

    if request.method == 'POST':
        dados_antigos = dict(item)
        dados_novos = {'numero_caixa': request.form['numero_caixa']}
        db.execute("UPDATE contas_a_pagar_diversos SET numero_caixa = ? WHERE id = ?", (dados_novos['numero_caixa'], item_id))
        db.commit()
        log_action('edit_documento_diverso', target_id=item_id, target_name=f"Caixa {dados_novos['numero_caixa']}", dados_antigos=dados_antigos, dados_novos=dados_novos)
        flash('Documento atualizado com sucesso!', 'success')
        return redirect(url_for('documentos_diversos_dashboard'))
    return render_template('contas_a_pagar/documentos_diversos_edit.html', item=item)


# --- Rotas de API (Ex: Reordenar) ---
@app.route('/cobranca/fichas_acerto/update_order', methods=['POST'])
@login_required
@role_required(['super_admin', 'admin_cobranca'])
def cobranca_fichas_acerto_update_order():
    data = request.get_json()
    ordered_ids = data.get('order')
    if not ordered_ids:
        return jsonify({'status': 'error', 'message': 'Nenhuma ordem fornecida.'}), 400
    db = get_db()
    try:
        if session['role'] != 'super_admin':
            placeholders = ','.join('?' for _ in ordered_ids)
            params = ordered_ids + [session.get('store_id')]
            count = db.execute(f"SELECT COUNT(id) FROM cobranca_fichas_acerto WHERE id IN ({placeholders}) AND store_id = ?", params).fetchone()[0]
            if count != len(ordered_ids):
                return jsonify({'status': 'error', 'message': 'Permissão negada para um ou mais itens.'}), 403
        
        for index, item_id in enumerate(ordered_ids):
            db.execute("UPDATE cobranca_fichas_acerto SET order_position = ? WHERE id = ?", (index, item_id))
        db.commit()
        log_action('reorder_fichas_acerto')
        return jsonify({'status': 'success', 'message': 'Ordem atualizada com sucesso!'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Erro ao reordenar fichas: {e}")
        return jsonify({'status': 'error', 'message': 'Ocorreu um erro interno.'}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)