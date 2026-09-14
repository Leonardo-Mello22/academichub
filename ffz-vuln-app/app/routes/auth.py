import hashlib
import os
from flask import Blueprint, request, session, redirect, render_template, url_for
from app.database import unsafe_query, execute_db, query_db

auth_bp = Blueprint('auth', __name__)


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULN V-03: SQL Injection por concatenação de string
        # VULN V-16: Sem rate limiting ou bloqueio por tentativas
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{md5(password)}'"
        results = unsafe_query(query)

        if not results:
            # VULN V-11: Mensagens de erro diferenciadas revelam existência de usuário
            user_check = unsafe_query(f"SELECT id FROM users WHERE username='{username}'")
            if not user_check:
                error = "Usuário não encontrado."
            else:
                error = "Senha incorreta."
        else:
            user = results[0]
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            session['full_name'] = user[5]
            return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html', error=error)


@auth_bp.route('/registro', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '')

        # VULN V-17: Sem validação de complexidade de senha
        # VULN V-11: Mensagem de erro revela que o usuário já existe
        # VULN V-03: Inserção por concatenação de string
        existing = unsafe_query(f"SELECT id FROM users WHERE username='{username}'")
        if existing:
            error = f"O nome de usuário '{username}' já está em uso."
        else:
            existing_email = unsafe_query(f"SELECT id FROM users WHERE email='{email}'")
            if existing_email:
                error = f"O e-mail '{email}' já está cadastrado."
            else:
                unsafe_query(
                    f"INSERT INTO users (username, email, password, full_name) "
                    f"VALUES ('{username}', '{email}', '{md5(password)}', '{full_name}')"
                )
                return redirect(url_for('auth.login'))

    return render_template('auth/register.html', error=error)


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@auth_bp.route('/recuperar-senha', methods=['GET', 'POST'])
def forgot_password():
    msg = None
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '')
        # VULN V-11: Revela se o e-mail está ou não cadastrado
        user = unsafe_query(f"SELECT id FROM users WHERE email='{email}'")
        if not user:
            error = "Nenhuma conta encontrada com este e-mail."
        else:
            user_id = user[0][0]
            # VULN V-14: Token sequencial e sem expiração
            last = query_db("SELECT MAX(token) FROM password_reset_tokens", one=True)
            next_token = (last[0] or 1000) + 1
            execute_db(
                "INSERT INTO password_reset_tokens (user_id, token, used) VALUES (%s, %s, 0)",
                (user_id, next_token)
            )
            msg = f"Link de recuperação gerado. Acesse: /redefinir-senha/{next_token}"

    return render_template('auth/forgot_password.html', msg=msg, error=error)


@auth_bp.route('/redefinir-senha/<int:token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    # VULN V-14: Token sem expiração e sem verificação de uso único
    record = query_db("SELECT * FROM password_reset_tokens WHERE token=%s", (token,), one=True)
    if not record:
        return render_template('auth/reset_password.html', error="Token inválido.", valid=False)

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        # VULN V-17: Sem validação de complexidade
        execute_db("UPDATE users SET password=%s WHERE id=%s", (md5(new_password), record[1]))
        # Não marca como usado — VULN V-14: token reutilizável
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token, valid=True, error=error)
