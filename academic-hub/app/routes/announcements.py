from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import vulnerable_query, execute_db, query_db

announcements_bp = Blueprint('announcements', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@announcements_bp.route('/')
def list_announcements():
    redir = require_login()
    if redir:
        return redir

    announcements = vulnerable_query(
        "SELECT a.id, a.title, a.body, a.created_at, u.full_name, c.name "
        "FROM announcements a "
        "JOIN users u ON a.author_id = u.id "
        "LEFT JOIN courses c ON a.course_id = c.id "
        "ORDER BY a.created_at DESC"
    )
    return render_template('announcements/list.html', announcements=announcements)


@announcements_bp.route('/novo', methods=['GET', 'POST'])
def new_announcement():
    redir = require_login()
    if redir:
        return redir

    if session.get('role') not in ('professor', 'admin'):
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title', '')
        body = request.form.get('body', '')
        course_id = request.form.get('course_id') or None
        author_id = session['user_id']
    
        execute_db(
            "INSERT INTO announcements (title, body, author_id, course_id) VALUES (%s, %s, %s, %s)",
            (title, body, author_id, course_id)
        )
        return redirect(url_for('announcements.list_announcements'))

    courses = query_db("SELECT id, code, name FROM courses ORDER BY code")
    return render_template('announcements/new.html', courses=courses)
