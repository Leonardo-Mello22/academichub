import mimetypes
import os
import time

from flask import (
    Blueprint,
    Response,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.bigdata.crypto_ops import (
    decrypt,
    encrypt,
    get_app_key,
    is_encrypted_envelope,
)
from app.bigdata.events import log_security_event
from app.crypto import DecryptionError
from app.database import (
    execute_db,
    query_db,
)

files_bp = Blueprint('files', __name__)

UPLOAD_FOLDER = os.environ.get(
    'UPLOAD_FOLDER',
    '/app/uploads'
)


def require_login():
    if not session.get('user_id'):
        return redirect(
            url_for('auth.login')
        )

    return None


@files_bp.route('/')
def list_files():
    redir = require_login()

    if redir:
        return redir

    files = query_db(
        "SELECT "
        "u.id, "
        "u.original_name, "
        "u.filename, "
        "u.uploaded_at, "
        "usr.full_name, "
        "c.name "
        "FROM uploads u "
        "JOIN users usr "
        "ON u.uploader_id = usr.id "
        "LEFT JOIN courses c "
        "ON u.course_id = c.id "
        "ORDER BY u.uploaded_at DESC"
    )

    courses = query_db(
        "SELECT id, code, name "
        "FROM courses "
        "ORDER BY code"
    )

    return render_template(
        'files/list.html',
        files=files,
        courses=courses
    )


@files_bp.route('/upload', methods=['POST'])
def upload_file():
    redir = require_login()

    if redir:
        return redir

    if 'file' not in request.files:
        return redirect(
            url_for('files.list_files')
        )

    f = request.files['file']

    course_id = (
        request.form.get('course_id')
        or None
    )

    if f.filename == '':
        return redirect(
            url_for('files.list_files')
        )

    original_name = f.filename

    save_name = (
        f"{int(time.time())}_{original_name}"
    )

    save_path = os.path.join(
        UPLOAD_FOLDER,
        save_name
    )

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    raw = f.read()
    envelope = encrypt(
        raw,
        get_app_key(),
        context='files',
    )

    with open(save_path, 'wb') as out:
        out.write(envelope)

    execute_db(
        """
        INSERT INTO uploads (
            uploader_id,
            course_id,
            filename,
            original_name
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            session['user_id'],
            course_id,
            save_name,
            original_name
        )
    )

    log_security_event(
        'FILE_UPLOAD',
        f'Upload de arquivo: {original_name}',
        severity='INFO',
        details={
            'saved_as': save_name,
            'course_id': course_id,
            'encrypted': True,
            'plaintext_bytes': len(raw),
        },
    )

    return redirect(
        url_for('files.list_files')
    )


@files_bp.route('/baixar/<path:filename>')
def download_file(filename):
    redir = require_login()
    if redir:
        return redir

    filepath = os.path.normpath(
        os.path.join(
            UPLOAD_FOLDER,
            filename
        )
    )

    if '..' in filename or filename.startswith('/'):
        log_security_event(
            'FILE_DOWNLOAD_SUSPICIOUS',
            f'Download com path suspeito: {filename}',
            severity='HIGH',
            details={'resolved': filepath},
        )

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        if is_encrypted_envelope(data):
            try:
                plain = decrypt(
                    data,
                    get_app_key(),
                    context='files',
                )
            except DecryptionError:
                abort(500)
        else:
            # Upload legado (antes da integração da cifra).
            plain = data

        mime, _ = mimetypes.guess_type(filename)
        mime = mime or 'application/octet-stream'

        return Response(plain, mimetype=mime)

    except FileNotFoundError:
        abort(404)

    except PermissionError:
        abort(403)
