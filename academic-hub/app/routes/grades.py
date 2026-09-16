from flask import (
    Blueprint,
    request,
    session,
    redirect,
    render_template,
    url_for,
    abort,
)

from app.database import execute_db, query_db


grades_bp = Blueprint('grades', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(
            url_for('auth.login')
        )

    return None


@grades_bp.route('/')
def list_grades():
    redir = require_login()

    if redir:
        return redir

    user_id = session['user_id']
    role = session.get('role')

    filtro = request.args.get(
        'filtro',
        ''
    )

    if role == 'aluno':
        grades = query_db(
            """
            SELECT
                g.id,
                g.assignment_name,
                g.grade,
                g.feedback,
                c.name,
                c.code
            FROM grades g
            JOIN courses c
                ON g.course_id = c.id
            WHERE g.student_id = %s
            ORDER BY g.created_at DESC
            """,
            (user_id,),
        )

    else:
        grades = query_db(
            """
            SELECT
                g.id,
                g.assignment_name,
                g.grade,
                g.feedback,
                c.name,
                c.code,
                u.full_name
            FROM grades g
            JOIN courses c
                ON g.course_id = c.id
            JOIN users u
                ON g.student_id = u.id
            ORDER BY g.created_at DESC
            """
        )

    return render_template(
        'grades/list.html',
        grades=grades,
        role=role,
        filtro=filtro,
    )


@grades_bp.route('/<int:grade_id>')
def view_grade(grade_id):
    redir = require_login()

    if redir:
        return redir

    user_id = session['user_id']
    role = session.get('role')

    # Alunos só podem visualizar notas próprias.
    if role == 'aluno':
        grade = query_db(
            """
            SELECT
                g.*,
                c.name AS course_name,
                u.full_name AS student_name
            FROM grades g
            JOIN courses c
                ON g.course_id = c.id
            JOIN users u
                ON g.student_id = u.id
            WHERE g.id = %s
              AND g.student_id = %s
            """,
            (
                grade_id,
                user_id,
            ),
            one=True,
        )

        if not grade:
            abort(403)

    # Professor e administrador podem consultar
    # notas de outros alunos.
    else:
        grade = query_db(
            """
            SELECT
                g.*,
                c.name AS course_name,
                u.full_name AS student_name
            FROM grades g
            JOIN courses c
                ON g.course_id = c.id
            JOIN users u
                ON g.student_id = u.id
            WHERE g.id = %s
            """,
            (grade_id,),
            one=True,
        )

        if not grade:
            abort(404)

    return render_template(
        'grades/detail.html',
        grade=grade,
    )


@grades_bp.route('/aluno/<int:student_id>')
def student_grades(student_id):
    redir = require_login()

    if redir:
        return redir

    user_id = session['user_id']
    role = session.get('role')

    # Aluno não pode consultar o boletim
    # completo de outro aluno.
    if (
        role == 'aluno'
        and student_id != user_id
    ):
        abort(403)

    student = query_db(
        """
        SELECT *
        FROM users
        WHERE id = %s
        """,
        (student_id,),
        one=True,
    )

    if not student:
        abort(404)

    grades = query_db(
        """
        SELECT
            g.id,
            g.assignment_name,
            g.grade,
            g.feedback,
            c.name
        FROM grades g
        JOIN courses c
            ON g.course_id = c.id
        WHERE g.student_id = %s
        """,
        (student_id,),
    )

    return render_template(
        'grades/student.html',
        student=student,
        grades=grades,
    )


@grades_bp.route(
    '/lancar',
    methods=['GET', 'POST'],
)
def submit_grade():
    redir = require_login()

    if redir:
        return redir

    role = session.get('role')

    # Apenas professores e administradores
    # podem lançar notas.
    if role not in (
        'professor',
        'admin',
    ):
        abort(403)

    if request.method == 'POST':
        student_id = request.form.get(
            'student_id'
        )

        course_id = request.form.get(
            'course_id'
        )

        assignment_name = request.form.get(
            'assignment_name',
            ''
        )

        grade = request.form.get(
            'grade'
        )

        feedback = request.form.get(
            'feedback',
            ''
        )

        # Não confiar em professor_id vindo
        # do formulário.
        submitted_by = session['user_id']

        execute_db(
            """
            INSERT INTO grades (
                student_id,
                course_id,
                assignment_name,
                grade,
                feedback,
                submitted_by
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                student_id,
                course_id,
                assignment_name,
                grade,
                feedback,
                submitted_by,
            ),
        )

        from app.security_log import (
            log_security_event,
        )

        log_security_event(
            'GRADE_SUBMIT',
            (
                f'Nota lançada: '
                f'{assignment_name} = {grade}'
            ),
            severity='INFO',
            details=(
                f'student_id={student_id}; '
                f'course_id={course_id}; '
                f'submitted_by={submitted_by}; '
                f'session_user={session.get("user_id")}'
            ),
        )

        return redirect(
            url_for('grades.list_grades')
        )

    students = query_db(
        """
        SELECT
            id,
            full_name,
            student_id
        FROM users
        WHERE role = 'aluno'
        ORDER BY full_name
        """
    )

    courses = query_db(
        """
        SELECT
            id,
            code,
            name
        FROM courses
        ORDER BY code
        """
    )

    professors = query_db(
        """
        SELECT
            id,
            full_name
        FROM users
        WHERE role = 'professor'
        ORDER BY full_name
        """
    )

    return render_template(
        'grades/submit.html',
        students=students,
        courses=courses,
        professors=professors,
    )
