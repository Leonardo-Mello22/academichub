from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import unsafe_query, execute_db, query_db

grades_bp = Blueprint('grades', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@grades_bp.route('/')
def list_grades():
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    role = session.get('role')

    # VULN V-01: Parâmetro 'filtro' refletido sem escape no template
    filtro = request.args.get('filtro', '')

    if role == 'aluno':
        grades = unsafe_query(
            f"SELECT g.id, g.assignment_name, g.grade, g.feedback, c.name, c.code "
            f"FROM grades g JOIN courses c ON g.course_id = c.id "
            f"WHERE g.student_id = {user_id} ORDER BY g.created_at DESC"
        )
    else:
        grades = unsafe_query(
            "SELECT g.id, g.assignment_name, g.grade, g.feedback, c.name, c.code, u.full_name "
            "FROM grades g JOIN courses c ON g.course_id = c.id "
            "JOIN users u ON g.student_id = u.id ORDER BY g.created_at DESC"
        )

    return render_template('grades/list.html', grades=grades, role=role, filtro=filtro)


@grades_bp.route('/<int:grade_id>')
def view_grade(grade_id):
    redir = require_login()
    if redir:
        return redir

    # VULN V-06: Sem verificação de propriedade — qualquer aluno acessa qualquer nota
    result = unsafe_query(
        f"SELECT g.*, c.name as course_name, u.full_name as student_name "
        f"FROM grades g JOIN courses c ON g.course_id = c.id "
        f"JOIN users u ON g.student_id = u.id "
        f"WHERE g.id = {grade_id}"
    )
    if not result:
        abort(404)
    return render_template('grades/detail.html', grade=result[0])


@grades_bp.route('/aluno/<int:student_id>')
def student_grades(student_id):
    redir = require_login()
    if redir:
        return redir

    # VULN V-06: Sem restrição de papel — aluno pode ver notas de outro aluno
    student = unsafe_query(f"SELECT * FROM users WHERE id = {student_id}")
    if not student:
        abort(404)
    grades = unsafe_query(
        f"SELECT g.id, g.assignment_name, g.grade, g.feedback, c.name FROM grades g "
        f"JOIN courses c ON g.course_id = c.id WHERE g.student_id = {student_id}"
    )
    return render_template('grades/student.html', student=student[0], grades=grades)


@grades_bp.route('/lancar', methods=['GET', 'POST'])
def submit_grade():
    redir = require_login()
    if redir:
        return redir

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        assignment_name = request.form.get('assignment_name', '')
        grade = request.form.get('grade')
        feedback = request.form.get('feedback', '')
        # VULN V-10: professor_id vem do corpo do POST, não da sessão
        # VULN V-05: Sem token CSRF
        professor_id = request.form.get('professor_id')

        execute_db(
            "INSERT INTO grades (student_id, course_id, assignment_name, grade, feedback, submitted_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (student_id, course_id, assignment_name, grade, feedback, professor_id)
        )
        from app.security_log import log_security_event
        log_security_event(
            'GRADE_SUBMIT',
            f'Nota lançada: {assignment_name} = {grade}',
            severity='INFO',
            details=(
                f'student_id={student_id}; course_id={course_id}; '
                f'submitted_by={professor_id}; session_user={session.get("user_id")}'
            ),
        )
        return redirect(url_for('grades.list_grades'))

    students = query_db("SELECT id, full_name, student_id FROM users WHERE role='aluno' ORDER BY full_name")
    courses = query_db("SELECT id, code, name FROM courses ORDER BY code")
    professors = query_db("SELECT id, full_name FROM users WHERE role='professor' ORDER BY full_name")

    return render_template('grades/submit.html', students=students, courses=courses, professors=professors)
