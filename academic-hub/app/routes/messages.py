from flask import Blueprint, request, session, redirect, render_template, url_for, abort
from app.database import vulnerable_query, execute_db, query_db

messages_bp = Blueprint('messages', __name__)


def require_login():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return None


@messages_bp.route('/')
def inbox():
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    messages = vulnerable_query(
        f"SELECT m.id, m.subject, m.is_read, m.sent_at, u.full_name, u.username "
        f"FROM messages m JOIN users u ON m.sender_id = u.id "
        f"WHERE m.recipient_id = {user_id} ORDER BY m.sent_at DESC"
    )
    return render_template('messages/inbox.html', messages=messages)


@messages_bp.route('/<int:message_id>')
def read_message(message_id):
    redir = require_login()
    if redir:
        return redir

    user_id = session['user_id']
    
    msg = vulnerable_query(
        f"SELECT m.*, u.full_name as sender_name, u.username as sender_username "
        f"FROM messages m JOIN users u ON m.sender_id = u.id "
        f"WHERE m.id = {message_id}"
    )
    if not msg:
        abort(404)

    execute_db("UPDATE messages SET is_read=1 WHERE id=%s", (message_id,))
    return render_template('messages/read.html', msg=msg[0])


@messages_bp.route('/nova', methods=['GET', 'POST'])
def compose():
    redir = require_login()
    if redir:
        return redir

    if request.method == 'POST':
        recipient_username = request.form.get('recipient', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        sender_id = session['user_id']

        recipient = vulnerable_query(f"SELECT id FROM users WHERE username='{recipient_username}'")
        if recipient:
            execute_db(
                "INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (%s, %s, %s, %s)",
                (sender_id, recipient[0][0], subject, body)
            )
            return redirect(url_for('messages.inbox'))

    para = request.args.get('para', '')
    users = query_db("SELECT username, full_name FROM users ORDER BY full_name")
    return render_template('messages/compose.html', para=para, users=users)
