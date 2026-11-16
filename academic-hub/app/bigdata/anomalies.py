"""
Armazenamento dos eventos de detecção de anomalias (camada 4 — Big Data).

Qualquer detector — as regras de `app.bigdata.analysis` hoje, a IA da
camada 5 depois — registra o que encontrou com `record_anomaly()`. Cada
anomalia é gravada:

  1. na tabela `anomaly_events` (com status de tratamento), e
  2. como evento `ANOMALY_DETECTED` no fluxo de eventos de segurança
     (banco + JSONL), para entrar nas próprias análises de volume.

Exemplo:

    record_anomaly(
        'AUTH_ATTEMPTS',
        '57 falhas de login do IP 10.0.0.9 em 1h',
        subject='10.0.0.9',
        score=0.93,
        detector='regras',
        evidence={'failures': 57, 'window_hours': 1},
    )
"""

import json

from app.database import execute_db, query_db
from app.bigdata.events import log_security_event


# Os 5 tipos de anomalia pedidos no enunciado (camada 5).
ANOMALY_TYPES = {
    'AUTH_ATTEMPTS':   'Número incomum de tentativas de autenticação',
    'DECRYPT_FAILURES': 'Frequência elevada de falhas de descriptografia',
    'FILE_CHANGES':    'Alterações inesperadas em arquivos',
    'ACCESS_PATTERN':  'Padrões atípicos de acesso',
    'EVENT_VOLUME':    'Geração incomum de eventos',
}

STATUSES = ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')


def record_anomaly(
    anomaly_type,
    description,
    *,
    severity='HIGH',
    score=None,
    subject=None,
    detector='regras',
    evidence=None,
):
    """Persiste uma anomalia detectada. Retorna o id criado (ou None)."""
    if anomaly_type not in ANOMALY_TYPES:
        raise ValueError(
            f'Tipo de anomalia desconhecido: {anomaly_type}. '
            f'Use um de: {", ".join(ANOMALY_TYPES)}'
        )

    severity = severity.upper()
    evidence = evidence or {}

    anomaly_id = None
    try:
        anomaly_id = execute_db(
            """
            INSERT INTO anomaly_events
              (anomaly_type, severity, score, subject,
               detector, description, evidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (anomaly_type, severity, score, subject, detector,
             description, json.dumps(evidence, ensure_ascii=False, default=str)),
        )
    except Exception:
        # Sem banco (ex.: análise offline): ainda fica no JSONL abaixo.
        pass

    log_security_event(
        'ANOMALY_DETECTED',
        f'[{anomaly_type}] {description}',
        severity=severity,
        details={
            'anomaly_id': anomaly_id,
            'anomaly_type': anomaly_type,
            'subject': subject,
            'score': score,
            'detector': detector,
            'evidence': evidence,
        },
    )
    return anomaly_id


def list_anomalies(limit=100, anomaly_type=None, status=None):
    clauses = []
    args = []

    if anomaly_type:
        clauses.append('anomaly_type = %s')
        args.append(anomaly_type)

    if status:
        clauses.append('status = %s')
        args.append(status)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    args.append(limit)

    rows = query_db(
        f"""
        SELECT id, detected_at, anomaly_type, severity, score, subject,
               detector, description, evidence, status
        FROM anomaly_events
        {where}
        ORDER BY detected_at DESC, id DESC
        LIMIT %s
        """,
        tuple(args),
    )

    keys = ('id', 'detected_at', 'anomaly_type', 'severity', 'score',
            'subject', 'detector', 'description', 'evidence', 'status')
    return [dict(zip(keys, row)) for row in rows]


def set_anomaly_status(anomaly_id, status):
    if status not in STATUSES:
        raise ValueError(f'Status inválido: {status}')

    execute_db(
        'UPDATE anomaly_events SET status = %s WHERE id = %s',
        (status, anomaly_id),
    )


def anomaly_stats():
    """Contagem de anomalias abertas por tipo (todos os tipos aparecem)."""
    rows = query_db(
        """
        SELECT anomaly_type, COUNT(*)
        FROM anomaly_events
        WHERE status = 'OPEN'
        GROUP BY anomaly_type
        """
    )
    by_type = {name: 0 for name in ANOMALY_TYPES}
    by_type.update(dict(rows))

    return {'open': sum(by_type.values()), 'by_type': by_type}
