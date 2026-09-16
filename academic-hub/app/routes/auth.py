import hashlib

from flask import (
    Blueprint,
    request,
    session,
    redirect,
    render_template,
    url_for,
)

from app.database import (
    execute_db,
    query_db,
)


auth_bp = Blueprint('auth', __name__)


def md5(s):
    return hashlib.md5(
        s.encode()
    ).hexdigest()


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form.get(
            'username',
            ''
        )

        password = request.form.get(
            'password',
            ''
        )

        # V-03 corrigida:
        # consulta parametrizada impede que a entrada
        # do usuário altere a estrutura do SQL.
        user = query_db(
            """
            SELECT *
            FROM users
            WHERE username = %s
              AND password = %s
            """,
            (
                username,
                md5(password),
            ),
            one=True,
        )

        if not user:
            # Ainda mantém V-11 propositalmente.
            user_check = query_db(
                """
                SELECT id
                FROM users
                WHERE username = %s
                """,
                (username,),
                one=True,
            )

            if not user_check:
                error = "Usuário não encontrado."

            else:
                error = "Senha incorreta."

        else:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            session['full_name'] = user[5]

            return redirect(
                url_for('dashboard.index')
            )

    return render_template(
        'auth/login.html',
        error=error,
    )


@auth_bp.route('/registro', methods=['GET', 'POST'])
def register():
    error = None

    if request.method == 'POST':
        username = request.form.get(
            'username',
            ''
        )

        email = request.form.get(
            'email',
            ''
        )

        password = request.form.get(
            'password',
            ''
        )

        full_name = request.form.get(
            'full_name',
            ''
        )

        # V-03 corrigida também no registro.
        existing = query_db(
            """
            SELECT id
            FROM users
            WHERE username = %s
            """,
            (username,),
            one=True,
        )

        if existing:
            # V-11 permanece propositalmente.
            error = (
                f"O nome de usuário "
                f"'{username}' já está em uso."
            )

        else:
            existing_email = query_db(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,),
                one=True,
            )

            if existing_email:
                error = (
                    f"O e-mail "
                    f"'{email}' já está cadastrado."
                )

            else:
                execute_db(
                    """
                    INSERT INTO users (
                        username,
                        email,
                        password,
                        full_name
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        username,
                        email,
                        md5(password),
                        full_name,
                    ),
                )

                return redirect(
                    url_for('auth.login')
                )

    return render_template(
        'auth/register.html',
        error=error,
    )


@auth_bp.route('/logout')
def logout():
    session.clear()

    return redirect(
        url_for('auth.login')
    )


@auth_bp.route(
    '/recuperar-senha',
    methods=['GET', 'POST'],
)
def forgot_password():
    msg = None
    error = None

    if request.method == 'POST':
        email = request.form.get(
            'email',
            ''
        )

        # V-03 corrigida nesta consulta também.
        user = query_db(
            """
            SELECT id
            FROM users
            WHERE email = %s
            """,
            (email,),
            one=True,
        )

        # V-11 permanece propositalmente.
        if not user:
            error = (
                "Nenhuma conta encontrada "
                "com este e-mail."
            )

        else:
            user_id = user[0]

            # V-14 permanece propositalmente.
            last = query_db(
                """
                SELECT MAX(token)
                FROM password_reset_tokens
                """,
                one=True,
            )

            next_token = (
                (last[0] or 1000) + 1
            )

            execute_db(
                """
                INSERT INTO password_reset_tokens (
                    user_id,
                    token,
                    used
                )
                VALUES (%s, %s, 0)
                """,
                (
                    user_id,
                    next_token,
                ),
            )

            msg = (
                "Link de recuperação gerado. "
                f"Acesse: /redefinir-senha/{next_token}"
            )

    return render_template(
        'auth/forgot_password.html',
        msg=msg,
        error=error,
    )


@auth_bp.route(
    '/redefinir-senha/<int:token>',
    methods=['GET', 'POST'],
)
def reset_password(token):
    error = None

    # V-14 permanece propositalmente.
    record = query_db(
        """
        SELECT *
        FROM password_reset_tokens
        WHERE token = %s
        """,
        (token,),
        one=True,
    )

    if not record:
        return render_template(
            'auth/reset_password.html',
            error="Token inválido.",
            valid=False,
        )

    if request.method == 'POST':
        new_password = request.form.get(
            'password',
            ''
        )

        # V-13 e V-17 permanecem para correção posterior.
        execute_db(
            """
            UPDATE users
            SET password = %s
            WHERE id = %s
            """,
            (
                md5(new_password),
                record[1],
            ),
        )

        # V-14:
        # token ainda não é marcado como usado.
        return redirect(
            url_for('auth.login')
        )

    return render_template(
        'auth/reset_password.html',
        token=token,
        valid=True,
        error=error,
    )
