from flask import (
    Blueprint,
    request,
    session,
    redirect,
    render_template,
    url_for,
    abort,
)

from app.database import (
    query_db,
    execute_db,
)


profile_bp = Blueprint(
    'profile',
    __name__,
)


def require_login():
    if not session.get('user_id'):
        return redirect(
            url_for('auth.login')
        )

    return None


@profile_bp.route('/<int:user_id>')
def view_profile(user_id):
    redir = require_login()

    if redir:
        return redir

    # V-07 corrigida:
    # usuário comum só pode acessar o próprio perfil.
    if user_id != session['user_id']:
        abort(403)

    user = query_db(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (user_id,),
        one=True,
    )

    if not user:
        abort(404)

    return render_template(
        'profile/view.html',
        user=user,
    )


@profile_bp.route(
    '/editar',
    methods=['GET', 'POST'],
)
def edit_profile():
    redir = require_login()

    if redir:
        return redir

    user_id = session['user_id']

    user = query_db(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (user_id,),
        one=True,
    )

    if not user:
        abort(404)

    if request.method == 'POST':
        full_name = request.form.get(
            'full_name',
            ''
        )

        bio = request.form.get(
            'bio',
            ''
        )

        # V-09 permanece propositalmente vulnerável
        # para correção posterior.
        role = request.form.get(
            'role',
            'aluno'
        )

        execute_db(
            """
            UPDATE users
            SET full_name = %s,
                bio = %s,
                role = %s
            WHERE id = %s
            """,
            (
                full_name,
                bio,
                role,
                user_id,
            ),
        )

        session['role'] = role
        session['full_name'] = full_name

        return redirect(
            url_for(
                'profile.view_profile',
                user_id=user_id,
            )
        )

    return render_template(
        'profile/edit.html',
        user=user,
    )
