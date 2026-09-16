from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import vulnerable_query, execute_db, query_db
from app.security_log import log_security_event, list_security_logs, security_log_stats
import hashlib

admin_bp = Blueprint('admin', __name__)


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def require_admin():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    if session.get('role') != 'admin':
        log_security_event(
            'ADMIN_ACCESS_DENIED',
            f'Acesso negado ao painel admin por {session.get("username")}',
            severity='HIGH',
            details=f'role={session.get("role")}; path={request.path}',
        )
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
    sec = security_log_stats()
    return render_template('admin/dashboard.html', stats=stats, sec=sec)


@admin_bp.route('/logs')
def security_logs():
    err = require_admin()
    if err:
        return err

    event_type = request.args.get('event_type', '').strip() or None
    severity = request.args.get('severity', '').strip() or None
    logs = list_security_logs(limit=200, event_type=event_type, severity=severity)

    return render_template(
        'admin/security_logs.html',
        logs=logs,
        event_type=event_type or '',
        severity=severity or '',
    )


@admin_bp.route('/usuarios')
def users():
    err = require_admin()
    if err:
        return err

    all_users = vulnerable_query(
        "SELECT id, username, email, password, role, full_name, student_id, is_active, created_at FROM users ORDER BY id"
    )
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/usuarios/<int:user_id>/editar', methods=['GET', 'POST'])
def edit_user(user_id):
    err = require_admin()
    if err:
        return err

    user = vulnerable_query(f"SELECT * FROM users WHERE id = {user_id}")
    if not user:
        abort(404)
    user = user[0]

    if request.method == 'POST':
        role = request.form.get('role', 'aluno')
        is_active = 1 if request.form.get('is_active') else 0
        new_password = request.form.get('password', '')
        old_role = user[4]

        if new_password:
            execute_db(
                "UPDATE users SET role=%s, is_active=%s, password=%s WHERE id=%s",
                (role, is_active, md5(new_password), user_id)
            )
            log_security_event(
                'USER_UPDATE',
                f'Admin alterou usuário id={user_id} (senha redefinida)',
                severity='HIGH',
                details=f'target={user[1]}; role={old_role}->{role}; active={is_active}; password_changed=1',
            )
        else:
            execute_db(
                "UPDATE users SET role=%s, is_active=%s WHERE id=%s",
                (role, is_active, user_id)
            )
            log_security_event(
                'USER_UPDATE',
                f'Admin alterou usuário id={user_id}',
                severity='WARNING' if role != old_role else 'INFO',
                details=f'target={user[1]}; role={old_role}->{role}; active={is_active}',
            )

        if role != old_role:
            log_security_event(
                'ROLE_CHANGE',
                f'Papel alterado: {user[1]} ({old_role} -> {role})',
                severity='HIGH',
                details=f'target_user_id={user_id}',
            )

        return redirect(url_for('admin.users'))

    return render_template('admin/edit_user.html', user=user)


@admin_bp.route('/usuarios/<int:user_id>/deletar', methods=['POST'])
def delete_user(user_id):
    err = require_admin()
    if err:
        return err

    target = query_db(
        "SELECT username, role FROM users WHERE id=%s",
        (user_id,),
        one=True,
    )
    execute_db("DELETE FROM users WHERE id=%s", (user_id,))
    log_security_event(
        'USER_DELETE',
        f'Usuário deletado id={user_id}',
        severity='HIGH',
        details=(
            f'target={target[0]}; role={target[1]}'
            if target else f'target_user_id={user_id}'
        ),
    )
    return redirect(url_for('admin.users'))
