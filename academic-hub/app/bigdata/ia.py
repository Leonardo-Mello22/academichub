"""
Camada 5 — IA de detecção de anomalias (Isolation Forest).

Pipeline:

    eventos JSONL/banco
        → build_feature_table()   (vetor numérico por IP)
        → IsolationForest
        → lista no formato de find_patterns()
        → record_anomaly(detector='ia')

O modelo aprende o "perfil normal" de cada IP. Na detecção, IPs cujo
comportamento foge da distribuição são marcados e classificados em um dos
5 tipos do enunciado conforme a feature dominante.

Uso típico (CLI):

    python -m app.bigdata simular --sem-ataques --saida logs/normal.jsonl
    python -m app.bigdata ia treinar --arquivo logs/normal.jsonl
    python -m app.bigdata simular --saida logs/ataques.jsonl
    python -m app.bigdata ia detectar --arquivo logs/ataques.jsonl --registrar
"""

from __future__ import annotations

import os
from collections import defaultdict

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.bigdata.events import LOG_DIR


FEATURE_NAMES = (
    'login_success',
    'login_failure',
    'crypto_encrypt',
    'crypto_decrypt',
    'crypto_decrypt_failure',
    'file_upload',
    'file_suspicious',
    'admin_denied',
    'honeypot',
    'total',
)

DEFAULT_MODEL_PATH = os.path.join(LOG_DIR, 'models', 'isolation_forest.joblib')

# Contagem esperada de outliers no fit sem rótulos (painel admin).
DEFAULT_CONTAMINATION = 0.03


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------

def _empty_counts():
    return {name: 0 for name in FEATURE_NAMES}


def _bump(counts, event_type):
    counts['total'] += 1
    if event_type == 'LOGIN_SUCCESS':
        counts['login_success'] += 1
    elif event_type == 'LOGIN_FAILURE':
        counts['login_failure'] += 1
    elif event_type == 'CRYPTO_ENCRYPT':
        counts['crypto_encrypt'] += 1
    elif event_type == 'CRYPTO_DECRYPT':
        counts['crypto_decrypt'] += 1
    elif event_type == 'CRYPTO_DECRYPT_FAILURE':
        counts['crypto_decrypt_failure'] += 1
    elif event_type == 'FILE_UPLOAD':
        counts['file_upload'] += 1
    elif event_type == 'FILE_DOWNLOAD_SUSPICIOUS':
        counts['file_suspicious'] += 1
    elif event_type == 'ADMIN_ACCESS_DENIED':
        counts['admin_denied'] += 1
    elif event_type == 'HONEYPOT_TRIGGERED':
        counts['honeypot'] += 1


def build_feature_table(events, min_events=3):
    """
    Agrega eventos por IP e devolve (subjects, X, rows).

    subjects: lista de IPs
    X: ndarray (n, n_features)
    rows: lista de dicts de contagem (mesma ordem)
    """
    by_ip = defaultdict(_empty_counts)

    for ev in events:
        ip = ev.get('ip') or '-'
        if ip == '-':
            continue
        _bump(by_ip[ip], ev.get('event_type') or '')

    subjects = []
    rows = []
    for ip, counts in sorted(by_ip.items()):
        if counts['total'] < min_events:
            continue
        subjects.append(ip)
        rows.append(dict(counts))

    if not subjects:
        X = np.zeros((0, len(FEATURE_NAMES)), dtype=float)
    else:
        X = np.array(
            [[row[name] for name in FEATURE_NAMES] for row in rows],
            dtype=float,
        )

    return subjects, X, rows


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

def train_model(events, *, contamination=DEFAULT_CONTAMINATION, random_state=42):
    """Treina Isolation Forest no tráfego (idealmente normal) e devolve o modelo."""
    subjects, X, _ = build_feature_table(events)
    if len(subjects) < 5:
        raise ValueError(
            f'Poucos IPs para treinar ({len(subjects)}). '
            'Gere mais eventos com: python -m app.bigdata simular --sem-ataques'
        )

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)
    model.feature_names_ = list(FEATURE_NAMES)  # metadado nosso
    return model


def save_model(model, path=DEFAULT_MODEL_PATH):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(model, path)
    return path


def load_model(path=DEFAULT_MODEL_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f'Modelo não encontrado: {path}. '
            'Treine com: python -m app.bigdata ia treinar ...'
        )
    return joblib.load(path)


# ---------------------------------------------------------------------------
# Detecção
# ---------------------------------------------------------------------------

def _anomaly_score(decision_value):
    """Converte decision_function (mais negativo = mais anômalo) em [0.5, 1.0]."""
    # decision ~ tipicamente [-0.5, 0.5]; -decision alto → anomalia.
    raw = float(-decision_value)
    return round(min(1.0, max(0.5, 0.5 + raw)), 3)


def _types_for_row(row):
    """
    Um IP anômalo pode evidenciar vários ataques ao mesmo tempo
    (ex.: brute force + decrypt + path traversal). Emite um tipo por sinal forte.
    """
    types = []
    if row['login_failure'] >= 8:
        types.append('AUTH_ATTEMPTS')
    if row['crypto_decrypt_failure'] >= 5:
        types.append('DECRYPT_FAILURES')
    if row['file_suspicious'] >= 1 or row['file_upload'] >= 40:
        types.append('FILE_CHANGES')
    if row['honeypot'] >= 1 or row['admin_denied'] >= 3:
        types.append('ACCESS_PATTERN')
    if not types:
        # Outlier sem sinal clássico → volume atípico.
        types.append('EVENT_VOLUME')
    return types


def _severity_for(anomaly_type, score):
    if anomaly_type == 'ACCESS_PATTERN':
        return 'CRITICAL'
    if score >= 0.75:
        return 'HIGH'
    return 'WARNING'


def _describe(anomaly_type, subject, row):
    if anomaly_type == 'AUTH_ATTEMPTS':
        return (
            f'IA: {row["login_failure"]} falhas de login a partir do IP {subject} '
            f'({row["total"]} eventos)'
        )
    if anomaly_type == 'DECRYPT_FAILURES':
        return (
            f'IA: {row["crypto_decrypt_failure"]} falhas de decifragem '
            f'a partir do IP {subject}'
        )
    if anomaly_type == 'FILE_CHANGES':
        return (
            f'IA: atividade anômala em arquivos no IP {subject} '
            f'(suspeitos={row["file_suspicious"]}, uploads={row["file_upload"]})'
        )
    if anomaly_type == 'ACCESS_PATTERN':
        return (
            f'IA: padrão de acesso atípico no IP {subject} '
            f'(honeypot={row["honeypot"]}, admin_denied={row["admin_denied"]})'
        )
    return (
        f'IA: volume incomum de eventos no IP {subject} '
        f'({row["total"]} eventos)'
    )


def detect_anomalies(events, model=None, *, contamination=DEFAULT_CONTAMINATION):
    """
    Detecta IPs anômalos. Se `model` for None, treina Isolation Forest
    de forma não supervisionada sobre o próprio conjunto (útil no painel).
    """
    subjects, X, rows = build_feature_table(events)
    if len(subjects) == 0:
        return []

    if model is None:
        if len(subjects) < 5:
            return []
        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)

    preds = model.predict(X)
    decisions = model.decision_function(X)

    patterns = []
    for i, subject in enumerate(subjects):
        if preds[i] != -1:
            continue
        row = rows[i]
        score = _anomaly_score(decisions[i])
        for anomaly_type in _types_for_row(row):
            patterns.append({
                'anomaly_type': anomaly_type,
                'subject': subject,
                'description': _describe(anomaly_type, subject, row),
                'score': score,
                'severity': _severity_for(anomaly_type, score),
                'evidence': {
                    'detector': 'ia',
                    'features': row,
                    'decision': round(float(decisions[i]), 4),
                },
            })

    patterns.sort(key=lambda p: p['score'] or 0, reverse=True)
    return patterns


def store_ia_patterns(patterns):
    """Grava detecções da IA com detector='ia'."""
    from app.bigdata.analysis import store_patterns

    return store_patterns(patterns, detector='ia')
