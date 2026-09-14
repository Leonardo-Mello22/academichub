from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import unsafe_query, execute_db, query_db
import hashlib

admin_bp = Blueprint('admin', __name__)


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def require_admin():
    # VULN V-12: Verificação baseada no cookie de sessão — forjável com flask-unsign
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    if session.get('role') != 'admin':
        abort(403)
    return None


@admin_bp.route('/')
def dashboard():
    err = require_admin()
    if err:
        return err

    stats = {
        'users': query_db("SELECT COUNT(*) FROM users", one=True)[0],
        'courses': query_db("SELECT COUNT(*) FROM courses", one=True)[0],
        'grades': query_db("SELECT COUNT(*) FROM grades", one=True)[0],
        'messages': query_db("SELECT COUNT(*) FROM messages", one=True)[0],
    }
    return render_template('admin/dashboard.html', stats=stats)


@admin_bp.route('/usuarios')
def users():
    err = require_admin()
    if err:
        return err

    all_users = unsafe_query(
        "SELECT id, username, email, password, role, full_name, student_id, is_active, created_at FROM users ORDER BY id"
    )
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/usuarios/<int:user_id>/editar', methods=['GET', 'POST'])
def edit_user(user_id):
    err = require_admin()
    if err:
        return err

    user = unsafe_query(f"SELECT * FROM users WHERE id = {user_id}")
    if not user:
        abort(404)
    user = user[0]

    if request.method == 'POST':
        role = request.form.get('role', 'aluno')
        is_active = 1 if request.form.get('is_active') else 0
        new_password = request.form.get('password', '')

        if new_password:
            execute_db(
                "UPDATE users SET role=%s, is_active=%s, password=%s WHERE id=%s",
                (role, is_active, md5(new_password), user_id)
            )
        else:
            execute_db(
                "UPDATE users SET role=%s, is_active=%s WHERE id=%s",
                (role, is_active, user_id)
            )
        return redirect(url_for('admin.users'))

    return render_template('admin/edit_user.html', user=user)


@admin_bp.route('/usuarios/<int:user_id>/deletar', methods=['POST'])
def delete_user(user_id):
    err = require_admin()
    if err:
        return err

    execute_db("DELETE FROM users WHERE id=%s", (user_id,))
    return redirect(url_for('admin.users'))
