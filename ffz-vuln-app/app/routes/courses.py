from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import unsafe_query, execute_db

courses_bp = Blueprint('courses', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@courses_bp.route('/')
def list_courses():
    redir = require_login()
    if redir:
        return redir

    # VULN V-04: SQL Injection por UNION — parâmetro 'busca' concatenado na query
    busca = request.args.get('busca', '')

    if busca:
        courses = unsafe_query(
            f"SELECT id, code, name, description FROM courses WHERE name LIKE '%{busca}%'"
        )
    else:
        courses = unsafe_query(
            "SELECT id, code, name, description FROM courses ORDER BY code"
        )

    return render_template('courses/list.html', courses=courses, busca=busca)


@courses_bp.route('/<int:course_id>')
def course_detail(course_id):
    redir = require_login()
    if redir:
        return redir

    course = unsafe_query(
        f"SELECT c.*, u.full_name as professor_name FROM courses c "
        f"JOIN users u ON c.professor_id = u.id WHERE c.id = {course_id}"
    )
    if not course:
        abort(404)

    students = unsafe_query(
        f"SELECT u.id, u.full_name, u.student_id FROM enrollments e "
        f"JOIN users u ON e.student_id = u.id WHERE e.course_id = {course_id}"
    )

    user_id = session['user_id']
    enrolled = unsafe_query(
        f"SELECT id FROM enrollments WHERE student_id={user_id} AND course_id={course_id}"
    )

    return render_template('courses/detail.html', course=course[0], students=students, enrolled=bool(enrolled))


@courses_bp.route('/<int:course_id>/matricular', methods=['POST'])
def enroll(course_id):
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    already = unsafe_query(
        f"SELECT id FROM enrollments WHERE student_id={user_id} AND course_id={course_id}"
    )
    if not already:
        execute_db(
            "INSERT INTO enrollments (student_id, course_id) VALUES (%s, %s)",
            (user_id, course_id)
        )
    return redirect(url_for('courses.course_detail', course_id=course_id))
