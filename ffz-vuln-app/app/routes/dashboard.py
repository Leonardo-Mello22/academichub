from flask import Blueprint, request, session, redirect, render_template, url_for
from app.database import unsafe_query, query_db

dashboard_bp = Blueprint('dashboard', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@dashboard_bp.route('/')
@dashboard_bp.route('/painel')
def index():
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    role = session.get('role', 'aluno')

    # VULN V-01: Reflected XSS — parâmetro 'q' renderizado sem escape
    search_query = request.args.get('q', '')

    recent_grades = []
    enrolled_courses = []
    all_students = []

    if role == 'aluno':
        recent_grades = unsafe_query(
            f"SELECT g.assignment_name, g.grade, c.name FROM grades g "
            f"JOIN courses c ON g.course_id = c.id "
            f"WHERE g.student_id = {user_id} ORDER BY g.created_at DESC LIMIT 5"
        )
        enrolled_courses = unsafe_query(
            f"SELECT c.code, c.name FROM enrollments e "
            f"JOIN courses c ON e.course_id = c.id "
            f"WHERE e.student_id = {user_id}"
        )
    elif role in ('professor', 'admin'):
        all_students = query_db(
            "SELECT id, full_name, student_id, gpa FROM users WHERE role='aluno' ORDER BY full_name"
        )

    return render_template(
        'dashboard/index.html',
        search_query=search_query,
        recent_grades=recent_grades,
        enrolled_courses=enrolled_courses,
        all_students=all_students,
        role=role
    )
