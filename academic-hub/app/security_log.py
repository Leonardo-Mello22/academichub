"""Registro de eventos de segurança (auditoria)."""

import logging
import os

from flask import has_request_context, request, session

from app.database import execute_db, query_db


LOG_DIR = os.environ.get('SECURITY_LOG_DIR', '/app/logs')
LOG_FILE = os.path.join(LOG_DIR, 'security.log')

_file_logger = None


def _get_file_logger():
    global _file_logger

    if _file_logger is not None:
        return _file_logger

    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger('academichub.security')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        handler.setFormatter(
            logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
            )
        )
        logger.addHandler(handler)

    _file_logger = logger
    return logger


def _client_ip():
    if not has_request_context():
        return None

    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()

    return request.remote_addr


def _user_agent():
    if not has_request_context():
        return None

    return (request.headers.get('User-Agent') or '')[:500]


def log_security_event(
    event_type,
    message,
    *,
    severity='INFO',
    user_id=None,
    username=None,
    details=None,
):
    """
    Persiste um evento de segurança no banco e no arquivo security.log.

    event_type exemplos:
      LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, REGISTER,
      PASSWORD_RESET_REQUEST, PASSWORD_RESET,
      ROLE_CHANGE, USER_UPDATE, USER_DELETE,
      FILE_UPLOAD, GRADE_SUBMIT, ADMIN_ACCESS
    """
    if user_id is None and has_request_context():
        user_id = session.get('user_id')

    if username is None and has_request_context():
        username = session.get('username')

    ip = _client_ip()
    ua = _user_agent()
    severity = (severity or 'INFO').upper()
    details = details or ''

    try:
        execute_db(
            """
            INSERT INTO security_logs
              (event_type, severity, user_id, username, ip_address, user_agent, message, details)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event_type,
                severity,
                user_id,
                username,
                ip,
                ua,
                message,
                details,
            ),
        )
    except Exception as exc:
        # Evita que falha de log derrube a aplicação
        try:
            _get_file_logger().error(
                'Falha ao gravar security_log no banco: %s | event=%s msg=%s',
                exc,
                event_type,
                message,
            )
        except Exception:
            pass

    try:
        line = (
            f"{severity} | {event_type} | user={username or '-'} "
            f"(id={user_id or '-'}) | ip={ip or '-'} | {message}"
        )
        if details:
            line += f" | details={details}"

        logger = _get_file_logger()
        if severity in ('ERROR', 'CRITICAL', 'HIGH'):
            logger.error(line)
        elif severity == 'WARNING':
            logger.warning(line)
        else:
            logger.info(line)
    except Exception:
        pass


def list_security_logs(limit=100, event_type=None, severity=None):
    clauses = []
    args = []

    if event_type:
        clauses.append('event_type = %s')
        args.append(event_type)

    if severity:
        clauses.append('severity = %s')
        args.append(severity.upper())

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    args.append(limit)

    return query_db(
        f"""
        SELECT
          id,
          created_at,
          event_type,
          severity,
          user_id,
          username,
          ip_address,
          message,
          details
        FROM security_logs
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
        """,
        tuple(args),
    )


def security_log_stats():
    total = query_db('SELECT COUNT(*) FROM security_logs', one=True)
    failures = query_db(
        "SELECT COUNT(*) FROM security_logs WHERE event_type = 'LOGIN_FAILURE'",
        one=True,
    )
    today = query_db(
        """
        SELECT COUNT(*) FROM security_logs
        WHERE created_at::date = CURRENT_DATE
        """,
        one=True,
    )

    return {
        'total': total[0] if total else 0,
        'login_failures': failures[0] if failures else 0,
        'today': today[0] if today else 0,
    }
