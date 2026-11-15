"""
Gerador de eventos sintéticos para testar o processamento em grande volume.

Produz um arquivo JSONL no mesmo formato de `logs/security_events.jsonl`,
com tráfego "normal" e, opcionalmente, cenários de ataque injetados — um
para cada tipo de anomalia, para que a análise tenha o que encontrar:

  AUTH_ATTEMPTS     força bruta de um IP + ataque distribuído a um usuário
  DECRYPT_FAILURES  rajada de falhas de decifragem de um IP
  FILE_CHANGES      downloads com caminho suspeito (path traversal)
  ACCESS_PATTERN    senha honeypot usada + aluno tentando o painel admin
  EVENT_VOLUME      pico de eventos em uma hora específica
"""

import json
import os
import random
from datetime import datetime, timedelta

from app.bigdata.events import event_category


# Mistura do tráfego normal: (event_type, severity, peso)
NORMAL_MIX = (
    ('LOGIN_SUCCESS', 'INFO', 28),
    ('LOGIN_FAILURE', 'WARNING', 4),
    ('LOGOUT', 'INFO', 14),
    ('CRYPTO_ENCRYPT', 'INFO', 22),
    ('CRYPTO_DECRYPT', 'INFO', 22),
    ('CRYPTO_DECRYPT_FAILURE', 'WARNING', 1),
    ('FILE_UPLOAD', 'INFO', 4),
    ('GRADE_SUBMIT', 'INFO', 5),
)

ATTACKER_IP = '203.0.113.66'
STUFFING_TARGET = 'prof.silva'


def _event(ts, event_type, severity, user, ip, message, details=None):
    return {
        'ts': ts.isoformat(timespec='seconds'),
        'event_type': event_type,
        'category': event_category(event_type),
        'severity': severity,
        'user_id': None,
        'username': user,
        'ip': ip,
        'message': message,
        'details': details or {},
    }


def _crypto_details(rng, event_type):
    size = rng.choice((32, 64, 128, 512, 1024, 4096))
    details = {
        'context': rng.choice(('messages', 'files', 'grades')),
        'envelope_id': '%016x' % rng.getrandbits(64),
        'rounds': 16,
        'duration_ms': round(size / 16 * rng.uniform(0.5, 0.7), 3),  # ~0,6 ms/bloco
    }
    if event_type == 'CRYPTO_DECRYPT_FAILURE':
        details['reason'] = rng.choice((
            'Padding inválido (chave incorreta?).',
            'Envelope não reconhecido (magic inválido).',
        ))
    else:
        details['plaintext_bytes'] = size
    return details


def _normal_events(rng, n, start, hours, users, ips):
    types, sevs, weights = zip(*((t, s, w) for t, s, w in NORMAL_MIX))
    span = hours * 3600

    for _ in range(n):
        i = rng.choices(range(len(types)), weights=weights)[0]
        etype, sev = types[i], sevs[i]
        ts = start + timedelta(seconds=rng.randrange(span))
        user = rng.choice(users)
        details = (
            _crypto_details(rng, etype) if etype.startswith('CRYPTO_') else {}
        )
        yield _event(ts, etype, sev, user, rng.choice(ips),
                     f'{etype} (simulado)', details)


def _attack_events(rng, n, start, hours, users, ips):
    """Cenários de ataque, proporcionais ao volume total."""
    end = start + timedelta(hours=hours)
    k = max(1, n // 1000)

    def at(hours_before_end, jitter_s=3600):
        return end - timedelta(hours=hours_before_end) + timedelta(
            seconds=rng.randrange(jitter_s)
        )

    # Força bruta de um único IP contra o admin.
    for _ in range(30 * k):
        yield _event(at(5), 'LOGIN_FAILURE', 'WARNING', 'admin', ATTACKER_IP,
                     'Senha incorreta (simulado)', {'reason': 'wrong_password'})

    # Ataque distribuído (credential stuffing) a um professor.
    botnet = [f'198.51.100.{i}' for i in range(1, 21)]
    for _ in range(15 * k):
        yield _event(at(10), 'LOGIN_FAILURE', 'WARNING', STUFFING_TARGET,
                     rng.choice(botnet), 'Senha incorreta (simulado)',
                     {'reason': 'wrong_password'})

    # Rajada de falhas de decifragem (tentativa de adivinhar a chave).
    for _ in range(40 * k):
        yield _event(at(3), 'CRYPTO_DECRYPT_FAILURE', 'WARNING', 'aluno.x',
                     ATTACKER_IP, 'Falha de decifragem (simulado)',
                     _crypto_details(rng, 'CRYPTO_DECRYPT_FAILURE'))

    # Path traversal em downloads.
    for path in ('../../etc/passwd', '/app/entrypoint.py', '../.env'):
        yield _event(at(7), 'FILE_DOWNLOAD_SUSPICIOUS', 'HIGH', 'aluno.x',
                     ATTACKER_IP, f'Download com path suspeito: {path}',
                     {'filename': path})

    # Honeypot e aluno tentando o painel admin.
    yield _event(at(2), 'HONEYPOT_TRIGGERED', 'CRITICAL', 'joao.aluno',
                 ATTACKER_IP, 'Login com senha honeypot (simulado)')
    for _ in range(5):
        yield _event(at(2), 'ADMIN_ACCESS_DENIED', 'HIGH', 'aluno.x',
                     ATTACKER_IP, 'Acesso negado ao painel admin (simulado)')

    # Pico de volume: 15% a mais de eventos concentrados em uma hora.
    spike_start = (end - timedelta(hours=hours // 2)).replace(
        minute=0, second=0, microsecond=0
    )
    for ev in _normal_events(rng, int(n * 0.15), spike_start, 1, users, ips):
        yield ev


def generate(path, n_events=100_000, hours=72, with_attacks=True, seed=42):
    """Grava `n_events` eventos simulados em `path`. Retorna o total gravado."""
    rng = random.Random(seed)
    users = [f'aluno{i:03d}' for i in range(180)] + [
        f'prof{i:02d}' for i in range(20)
    ] + ['admin']
    ips = [f'10.0.{i // 250}.{i % 250 + 1}' for i in range(150)]
    start = (datetime.now() - timedelta(hours=hours)).replace(microsecond=0)

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    written = 0

    with open(path, 'w', encoding='utf-8') as fh:
        sources = [_normal_events(rng, n_events, start, hours, users, ips)]
        if with_attacks:
            sources.append(_attack_events(rng, n_events, start, hours, users, ips))

        for source in sources:
            for ev in source:
                fh.write(json.dumps(ev, ensure_ascii=False))
                fh.write('\n')
                written += 1

    return written
