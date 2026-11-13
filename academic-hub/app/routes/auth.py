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
from app.security_log import log_security_event
from app.stego import (
    build_credentials,
    md5,
    verify_password_image,
)


auth_bp = Blueprint('auth', __name__)


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

        # V-03 corrigida: consulta parametrizada.
        # A senha real NÃO está mais na coluna password: o hash
        # Argon2id fica escondido na imagem ps_images (esteganografia).
        user = query_db(
            """
            SELECT id, username, password, role,
                   full_name, ps_images
            FROM users
            WHERE username = %s
            """,
            (username,),
            one=True,
        )

        authenticated = False

        if user:
            user_id, _, honeypot_md5, _, _, ps_image = user

            if ps_image is not None:
                authenticated = verify_password_image(
                    ps_image,
                    password,
                )

                if (
                    not authenticated
                    and md5(password) == honeypot_md5
                ):
                    # Alguém quebrou o MD5 da coluna password e
                    # tentou usar a senha falsa: honeypot acionado.
                    log_security_event(
                        'HONEYPOT_TRIGGERED',
                        f'Login com senha honeypot para {username}',
                        severity='CRITICAL',
                        user_id=user_id,
                        username=username,
                        details=(
                            'A senha da coluna users.password (isca) foi '
                            'usada: indício de vazamento do banco.'
                        ),
                    )

            elif md5(password) == honeypot_md5:
                # Usuário legado (antes da esteganografia): a coluna
                # password ainda tem o MD5 real. Migra no primeiro login.
                authenticated = True
                honeypot, image = build_credentials(password)
                execute_db(
                    """
                    UPDATE users
                    SET password = %s, ps_images = %s
                    WHERE id = %s
                    """,
                    (honeypot, image, user_id),
                )

        if not user:
            # Ainda mantém V-11 propositalmente.
            error = "Usuário não encontrado."

        elif not authenticated:
            error = "Senha incorreta."

        else:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            session['full_name'] = user[4]

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
                honeypot, image = build_credentials(password)
                execute_db(
                    """
                    INSERT INTO users (
                        username,
                        email,
                        password,
                        ps_images,
                        full_name
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        username,
                        email,
                        honeypot,
                        image,
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
        honeypot, image = build_credentials(new_password)
        execute_db(
            """
            UPDATE users
            SET password = %s, ps_images = %s
            WHERE id = %s
            """,
            (
                honeypot,
                image,
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
