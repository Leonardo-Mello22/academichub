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
    search_students = []
    search_courses = []
    search_grades = []

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
            "SELECT id, full_name, student_id, gpa, username FROM users WHERE role='aluno' ORDER BY full_name"
        )

    if search_query:
        like = f"%{search_query}%"

        if role in ('professor', 'admin'):
            search_students = query_db(
                """
                SELECT id, full_name, student_id, gpa, username
                FROM users
                WHERE role = 'aluno'
                  AND (
                    full_name ILIKE %s
                    OR username ILIKE %s
                    OR COALESCE(student_id, '') ILIKE %s
                    OR email ILIKE %s
                  )
                ORDER BY full_name
                LIMIT 20
                """,
                (like, like, like, like),
            )
        else:
            # Aluno: busca colegas pela matrícula/nome (visão limitada)
            search_students = query_db(
                """
                SELECT id, full_name, student_id, gpa, username
                FROM users
                WHERE role = 'aluno'
                  AND (
                    full_name ILIKE %s
                    OR username ILIKE %s
                    OR COALESCE(student_id, '') ILIKE %s
                  )
                ORDER BY full_name
                LIMIT 20
                """,
                (like, like, like),
            )

        search_courses = query_db(
            """
            SELECT id, code, name, description
            FROM courses
            WHERE code ILIKE %s OR name ILIKE %s OR COALESCE(description, '') ILIKE %s
            ORDER BY code
            LIMIT 20
            """,
            (like, like, like),
        )

        if role == 'aluno':
            search_grades = query_db(
                """
                SELECT g.id, g.assignment_name, g.grade, c.name, c.code
                FROM grades g
                JOIN courses c ON g.course_id = c.id
                WHERE g.student_id = %s
                  AND (
                    g.assignment_name ILIKE %s
                    OR c.name ILIKE %s
                    OR c.code ILIKE %s
                  )
                ORDER BY g.created_at DESC
                LIMIT 20
                """,
                (user_id, like, like, like),
            )
        else:
            search_grades = query_db(
                """
                SELECT g.id, g.assignment_name, g.grade, c.name, c.code, u.full_name
                FROM grades g
                JOIN courses c ON g.course_id = c.id
                JOIN users u ON g.student_id = u.id
                WHERE g.assignment_name ILIKE %s
                   OR c.name ILIKE %s
                   OR c.code ILIKE %s
                   OR u.full_name ILIKE %s
                ORDER BY g.created_at DESC
                LIMIT 20
                """,
                (like, like, like, like),
            )

    return render_template(
        'dashboard/index.html',
        search_query=search_query,
        recent_grades=recent_grades,
        enrolled_courses=enrolled_courses,
        all_students=all_students,
        search_students=search_students,
        search_courses=search_courses,
        search_grades=search_grades,
        role=role
    )
