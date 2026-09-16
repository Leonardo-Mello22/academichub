from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import vulnerable_query, execute_db
from app.security_log import log_security_event

profile_bp = Blueprint('profile', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@profile_bp.route('/<int:user_id>')
def view_profile(user_id):
    redir = require_login()
    if redir:
        return redir

    result = vulnerable_query(f"SELECT * FROM users WHERE id = {user_id}")
    if not result:
        abort(404)
    return render_template('profile/view.html', user=result[0])


@profile_bp.route('/editar', methods=['GET', 'POST'])
def edit_profile():
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    user = vulnerable_query(f"SELECT * FROM users WHERE id = {user_id}")
    if not user:
        abort(404)
    user = user[0]

    if request.method == 'POST':
        full_name = request.form.get('full_name', '')
        bio = request.form.get('bio', '')
    
        role = request.form.get('role', 'aluno')

        execute_db(
            "UPDATE users SET full_name=%s, bio=%s, role=%s WHERE id=%s",
            (full_name, bio, role, user_id)
        )
        if role != user[4]:
            log_security_event(
                'ROLE_CHANGE',
                f'Usuário {session.get("username")} alterou próprio papel: {user[4]} -> {role}',
                severity='HIGH',
                details=f'via=profile_edit; old={user[4]}; new={role}',
            )
        session['role'] = role
        session['full_name'] = full_name
        return redirect(url_for('profile.view_profile', user_id=user_id))

    return render_template('profile/edit.html', user=user)
