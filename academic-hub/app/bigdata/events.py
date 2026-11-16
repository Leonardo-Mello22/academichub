"""
Coleta e armazenamento de eventos de segurança (camada 4 — Big Data).

Todo evento relevante do sistema passa por `log_security_event()` e é gravado
em dois destinos:

  1. Tabela `security_logs` (PostgreSQL) — consultas e painel admin.
  2. Arquivo `logs/security_events.jsonl` — um evento JSON por linha.
     É o formato usado no processamento em grande volume
     (`app.bigdata.analysis`), pois pode ser lido em fluxo, linha a linha.

Tipos de evento por categoria (prefixo do event_type):

  AUTH_*     não há prefixo único; ver AUTH_EVENTS abaixo
  CRYPTO_*   operações da AcademicCipher (ver app.bigdata.crypto_ops)
  ANOMALY_*  anomalias detectadas (ver app.bigdata.anomalies)
  demais     ações administrativas, arquivos, notas, etc.
"""

import json
import logging
import os
from datetime import datetime

from flask import has_request_context, request, session

from app.database import execute_db, query_db


# ---------------------------------------------------------------------------
# Catálogo de eventos
# ---------------------------------------------------------------------------

AUTH_EVENTS = (
    'LOGIN_SUCCESS',
    'LOGIN_FAILURE',
    'LOGOUT',
    'REGISTER',
    'REGISTER_FAILURE',
    'PASSWORD_RESET_REQUEST',
    'PASSWORD_RESET',
    'HONEYPOT_TRIGGERED',
    'ADMIN_ACCESS_DENIED',
)

CRYPTO_EVENTS = (
    'CRYPTO_ENCRYPT',
    'CRYPTO_DECRYPT',
    'CRYPTO_DECRYPT_FAILURE',
)

ANOMALY_EVENTS = (
    'ANOMALY_DETECTED',
)

SEVERITIES = ('INFO', 'WARNING', 'HIGH', 'ERROR', 'CRITICAL')


def event_category(event_type):
    """Agrupa um event_type em AUTH, CRYPTO, ANOMALY ou OTHER."""
    if event_type in AUTH_EVENTS:
        return 'AUTH'
    if event_type.startswith('CRYPTO_'):
        return 'CRYPTO'
    if event_type.startswith('ANOMALY_'):
        return 'ANOMALY'
    return 'OTHER'


# ---------------------------------------------------------------------------
# Destino em arquivo (JSON Lines)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
LOG_DIR = os.environ.get('SECURITY_LOG_DIR', os.path.join(_PROJECT_ROOT, 'logs'))
EVENTS_FILE = os.path.join(LOG_DIR, 'security_events.jsonl')

# SECURITY_LOG_DB=0 grava só no arquivo (útil em scripts sem banco).
WRITE_TO_DB = os.environ.get('SECURITY_LOG_DB', '1') != '0'

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
        handler = logging.FileHandler(EVENTS_FILE, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)

    _file_logger = logger
    return logger


def _write_jsonl(record):
    try:
        _get_file_logger().info(json.dumps(record, ensure_ascii=False, default=str))
    except Exception:
        # Falha de log nunca pode derrubar a aplicação.
        pass


# ---------------------------------------------------------------------------
# Contexto da requisição
# ---------------------------------------------------------------------------

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


def _format_details(details):
    """Aceita dict (gravado como JSON) ou texto livre."""
    if not details:
        return ''
    if isinstance(details, dict):
        return json.dumps(details, ensure_ascii=False, default=str)
    return str(details)


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def log_security_event(
    event_type,
    message,
    *,
    severity='INFO',
    user_id=None,
    username=None,
    details=None,
    ip_address=None,
):
    """Registra um evento de segurança no banco e no arquivo JSONL."""
    if user_id is None and has_request_context():
        user_id = session.get('user_id')

    if username is None and has_request_context():
        username = session.get('username')

    ip = ip_address or _client_ip()
    ua = _user_agent()
    severity = (severity or 'INFO').upper()
    details_text = _format_details(details)

    if WRITE_TO_DB:
        try:
            execute_db(
                """
                INSERT INTO security_logs
                  (event_type, severity, user_id, username,
                   ip_address, user_agent, message, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (event_type, severity, user_id, username,
                 ip, ua, message, details_text),
            )
        except Exception as exc:
            _write_jsonl({
                'ts': datetime.now().isoformat(timespec='seconds'),
                'event_type': 'LOG_DB_ERROR',
                'severity': 'ERROR',
                'message': f'Falha ao gravar no banco: {exc}',
                'details': {'original_event': event_type},
            })

    _write_jsonl({
        'ts': datetime.now().isoformat(timespec='seconds'),
        'event_type': event_type,
        'category': event_category(event_type),
        'severity': severity,
        'user_id': user_id,
        'username': username,
        'ip': ip,
        'message': message,
        'details': details if isinstance(details, dict) else details_text,
    })


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
        SELECT id, created_at, event_type, severity, user_id,
               username, ip_address, message, details
        FROM security_logs
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT %s
        """,
        tuple(args),
    )


def security_log_stats():
    row = query_db(
        """
        SELECT
          COUNT(*),
          COUNT(*) FILTER (WHERE event_type = 'LOGIN_FAILURE'),
          COUNT(*) FILTER (WHERE created_at::date = CURRENT_DATE),
          COUNT(*) FILTER (WHERE event_type LIKE 'CRYPTO%%')
        FROM security_logs
        """,
        one=True,
    ) or (0, 0, 0, 0)

    return {
        'total': row[0],
        'login_failures': row[1],
        'today': row[2],
        'crypto_ops': row[3],
    }


# ---------------------------------------------------------------------------
# Importação em lote (simulação → dashboard)
# ---------------------------------------------------------------------------

_INSERT_SQL = """
    INSERT INTO security_logs
      (event_type, severity, user_id, username,
       ip_address, user_agent, message, details, created_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def _row_from_event(ev):
    """Converte um evento (dict JSONL) em tupla para INSERT."""
    details = ev.get('details')
    if isinstance(details, dict):
        details_text = json.dumps(details, ensure_ascii=False, default=str)
    else:
        details_text = details or ''

    ts = ev.get('ts') or ev.get('created_at')
    if isinstance(ts, datetime):
        created_at = ts
    elif isinstance(ts, str) and ts:
        try:
            created_at = datetime.fromisoformat(ts)
        except ValueError:
            created_at = datetime.now()
    else:
        created_at = datetime.now()

    return (
        ev.get('event_type') or 'UNKNOWN',
        (ev.get('severity') or 'INFO').upper(),
        ev.get('user_id'),
        ev.get('username'),
        ev.get('ip') or ev.get('ip_address'),
        ev.get('user_agent'),
        ev.get('message') or (ev.get('event_type') or 'evento'),
        details_text,
        created_at,
    )


def delete_simulated_events():
    """Remove eventos marcados como '(simulado)' — útil antes de reimportar."""
    from app.database import get_db

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM security_logs WHERE message LIKE %s",
                ('%(simulado)%',),
            )
            return cur.rowcount
    finally:
        conn.close()


def import_events_to_db(events, *, batch_size=2000):
    """
    Insere um iterável de eventos no PostgreSQL em lotes (executemany).
    Preserva `ts` como `created_at` para os gráficos por hora.
    Retorna quantos registros foram inseridos.
    """
    from app.database import get_db

    conn = get_db()
    inserted = 0
    batch = []

    try:
        with conn.cursor() as cur:
            for ev in events:
                batch.append(_row_from_event(ev))
                if len(batch) >= batch_size:
                    cur.executemany(_INSERT_SQL, batch)
                    inserted += len(batch)
                    batch.clear()
            if batch:
                cur.executemany(_INSERT_SQL, batch)
                inserted += len(batch)
        return inserted
    finally:
        conn.close()


def import_jsonl_to_db(path, *, batch_size=2000):
    """Lê um arquivo JSONL e grava no banco. Retorna o total inserido."""
    def _iter():
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue

    return import_events_to_db(_iter(), batch_size=batch_size)
