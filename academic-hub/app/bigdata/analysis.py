"""
Análise de padrões em grande volume de eventos (camada 4 — Big Data).

Pipeline:

    fonte de eventos  ──►  EventAggregator  ──►  relatório  ──►  find_patterns()
    (JSONL ou banco)       (1 passada,           (contagens,      (padrões
                            memória ~constante)   séries, taxas)   suspeitos)

  * `iter_jsonl_events(path)`  lê o arquivo linha a linha (não carrega tudo).
  * `iter_db_events(...)`      lê o banco com cursor de servidor, em lotes.
  * `analyze(events)`          agrega tudo numa única passada.
  * `find_patterns(report)`    aplica regras estatísticas de base e devolve
                               os padrões suspeitos, já no formato de
                               `record_anomaly()` (ver app.bigdata.anomalies).

As regras aqui são a linha de base determinística; a IA da camada 5 pode
consumir o mesmo relatório/eventos e registrar suas detecções pela mesma API.
"""

import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime

from app.bigdata.events import event_category


# Limiares das regras de base (podem ser sobrescritos em find_patterns).
#
# As contagens por IP/usuário usam DUAS condições: um mínimo absoluto E ser
# outlier em relação aos demais (z-score robusto, baseado em mediana/MAD).
# Assim a regra se adapta ao volume: com 1 milhão de eventos, todo IP
# legítimo passa de 20 falhas, mas só o atacante foge da distribuição.
DEFAULT_THRESHOLDS = {
    'auth_failures_per_ip': 20,      # falhas de login de um mesmo IP
    'auth_failures_per_user': 10,    # falhas contra um mesmo usuário...
    'auth_ips_per_user': 3,          # ...vindas de vários IPs
    'decrypt_min_attempts': 10,      # amostra mínima para avaliar a taxa
    'decrypt_failure_rate': 0.10,    # 10% de falhas de decifragem
    'decrypt_failures_per_ip': 10,
    'admin_denied_per_user': 3,
    'file_events_per_user': 30,
    'outlier_z': 3.5,                # z-score robusto mínimo
    'outlier_min_population': 5,     # abaixo disso, vale só o mínimo absoluto
    'volume_sigma': 3.0,             # pico = média + 3 desvios-padrão
    'volume_min_hours': 6,           # horas mínimas para ter uma média
}

TOP_N = 10


# ---------------------------------------------------------------------------
# Fontes de eventos (geradores — nada é carregado inteiro na memória)
# ---------------------------------------------------------------------------

def _parse_details(details):
    if isinstance(details, dict):
        return details
    if isinstance(details, str) and details.startswith('{'):
        try:
            return json.loads(details)
        except ValueError:
            pass
    return {}


def iter_jsonl_events(path):
    """Lê um arquivo JSONL de eventos, uma linha por vez."""
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue  # linha corrompida não interrompe a análise


def iter_db_events(window_hours=None, batch_size=5000):
    """Lê `security_logs` em lotes usando cursor de servidor (PostgreSQL)."""
    from app.database import get_db

    conn = get_db()
    conn.autocommit = False  # cursores nomeados exigem transação

    where = ''
    args = ()
    if window_hours:
        where = "WHERE created_at >= NOW() - (%s * INTERVAL '1 hour')"
        args = (window_hours,)

    try:
        with conn.cursor(name='bigdata_stream') as cur:
            cur.itersize = batch_size
            cur.execute(
                f"""
                SELECT created_at, event_type, severity, user_id,
                       username, ip_address, details
                FROM security_logs
                {where}
                ORDER BY created_at
                """,
                args,
            )
            for ts, etype, sev, uid, uname, ip, details in cur:
                yield {
                    'ts': ts.isoformat(timespec='seconds') if ts else '',
                    'event_type': etype,
                    'severity': sev,
                    'user_id': uid,
                    'username': uname,
                    'ip': ip,
                    'details': details,
                }
    finally:
        conn.rollback()
        conn.close()


# ---------------------------------------------------------------------------
# Agregação
# ---------------------------------------------------------------------------

class EventAggregator:
    """Acumula estatísticas evento a evento (uma única passada)."""

    def __init__(self):
        self.total = 0
        self.by_type = Counter()
        self.by_category = Counter()
        self.by_severity = Counter()
        self.by_hour = Counter()

        self.auth_success = 0
        self.auth_fail_by_ip = Counter()
        self.auth_fail_by_user = Counter()
        self.auth_fail_ips_by_user = defaultdict(set)
        self.honeypot = []
        self.admin_denied_by_user = Counter()

        self.crypto_encrypt = 0
        self.crypto_decrypt = 0
        self.crypto_fail = 0
        self.crypto_fail_by_ip = Counter()
        self.crypto_fail_reasons = Counter()
        self.crypto_bytes = 0
        self.crypto_ms_total = 0.0
        self.crypto_ms_count = 0

        self.file_events_by_user = Counter()
        self.file_suspicious_by_ip = Counter()

    def add(self, ev):
        etype = ev.get('event_type') or 'UNKNOWN'
        ip = ev.get('ip') or '-'
        user = ev.get('username') or '-'
        details = _parse_details(ev.get('details'))

        self.total += 1
        self.by_type[etype] += 1
        self.by_severity[ev.get('severity') or 'INFO'] += 1
        self.by_hour[str(ev.get('ts') or '')[:13]] += 1

        self.by_category[ev.get('category') or event_category(etype)] += 1

        if etype == 'LOGIN_SUCCESS':
            self.auth_success += 1
        elif etype == 'LOGIN_FAILURE':
            self.auth_fail_by_ip[ip] += 1
            self.auth_fail_by_user[user] += 1
            self.auth_fail_ips_by_user[user].add(ip)
        elif etype == 'HONEYPOT_TRIGGERED':
            self.honeypot.append({'ts': ev.get('ts'), 'user': user, 'ip': ip})
        elif etype == 'ADMIN_ACCESS_DENIED':
            self.admin_denied_by_user[user] += 1

        elif etype == 'CRYPTO_ENCRYPT':
            self.crypto_encrypt += 1
            self.crypto_bytes += details.get('plaintext_bytes', 0) or 0
            self._add_duration(details)
        elif etype == 'CRYPTO_DECRYPT':
            self.crypto_decrypt += 1
            self.crypto_bytes += details.get('plaintext_bytes', 0) or 0
            self._add_duration(details)
        elif etype == 'CRYPTO_DECRYPT_FAILURE':
            self.crypto_fail += 1
            self.crypto_fail_by_ip[ip] += 1
            self.crypto_fail_reasons[details.get('reason', '?')] += 1

        elif etype.startswith('FILE_'):
            self.file_events_by_user[user] += 1
            if etype == 'FILE_DOWNLOAD_SUSPICIOUS':
                self.file_suspicious_by_ip[ip] += 1

    def _add_duration(self, details):
        ms = details.get('duration_ms')
        if isinstance(ms, (int, float)):
            self.crypto_ms_total += ms
            self.crypto_ms_count += 1

    def report(self):
        decrypt_attempts = self.crypto_decrypt + self.crypto_fail
        auth_failures = sum(self.auth_fail_by_ip.values())

        return {
            'total': self.total,
            'by_category': dict(self.by_category),
            'by_type': dict(self.by_type.most_common()),
            'by_severity': dict(self.by_severity),
            'by_hour': dict(sorted(self.by_hour.items())),
            'auth': {
                'successes': self.auth_success,
                'failures': auth_failures,
                'top_failure_ips': self.auth_fail_by_ip.most_common(TOP_N),
                'top_failure_users': self.auth_fail_by_user.most_common(TOP_N),
                'ips_per_user': {
                    u: len(ips) for u, ips in self.auth_fail_ips_by_user.items()
                },
                'honeypot': self.honeypot[:TOP_N],
                'honeypot_total': len(self.honeypot),
                'admin_denied_by_user': self.admin_denied_by_user.most_common(TOP_N),
            },
            'crypto': {
                'encrypt': self.crypto_encrypt,
                'decrypt': self.crypto_decrypt,
                'decrypt_failures': self.crypto_fail,
                'decrypt_failure_rate': (
                    self.crypto_fail / decrypt_attempts if decrypt_attempts else 0.0
                ),
                'bytes_processed': self.crypto_bytes,
                'avg_duration_ms': (
                    self.crypto_ms_total / self.crypto_ms_count
                    if self.crypto_ms_count else 0.0
                ),
                'top_failure_ips': self.crypto_fail_by_ip.most_common(TOP_N),
                'failure_reasons': dict(self.crypto_fail_reasons.most_common(TOP_N)),
            },
            'files': {
                'top_users': self.file_events_by_user.most_common(TOP_N),
                'suspicious_by_ip': self.file_suspicious_by_ip.most_common(TOP_N),
            },
        }


def analyze(events):
    """Processa um iterável de eventos e devolve o relatório agregado."""
    agg = EventAggregator()
    start = time.perf_counter()

    for ev in events:
        agg.add(ev)

    elapsed = time.perf_counter() - start
    report = agg.report()
    report['processing'] = {
        'seconds': round(elapsed, 3),
        'events_per_second': round(agg.total / elapsed) if elapsed > 0 else agg.total,
        'analyzed_at': datetime.now().isoformat(timespec='seconds'),
    }
    # Mantém os conjuntos completos para as regras (não vão para o JSON final).
    report['_full'] = {
        'auth_fail_by_ip': agg.auth_fail_by_ip,
        'auth_fail_by_user': agg.auth_fail_by_user,
        'crypto_fail_by_ip': agg.crypto_fail_by_ip,
        'admin_denied_by_user': agg.admin_denied_by_user,
        'file_events_by_user': agg.file_events_by_user,
        'file_suspicious_by_ip': agg.file_suspicious_by_ip,
    }
    return report


def public_report(report):
    """Relatório sem os dados internos (pronto para JSON/template)."""
    return {k: v for k, v in report.items() if not k.startswith('_')}


# ---------------------------------------------------------------------------
# Regras de padrões suspeitos
# ---------------------------------------------------------------------------

def _score(value, threshold):
    """0.5 no limiar, tendendo a 1.0 conforme o valor cresce."""
    return round(min(1.0, 1 - 0.5 * threshold / max(value, threshold)), 3)


def _pattern(anomaly_type, subject, description, score, evidence, severity='HIGH'):
    return {
        'anomaly_type': anomaly_type,
        'subject': subject,
        'description': description,
        'score': score,
        'severity': severity,
        'evidence': evidence,
    }


def _outliers(counter, min_count, t):
    """
    Itens de `counter` com contagem >= min_count E atípicos na distribuição.

    z robusto = 0.6745 * (x - mediana) / MAD   (Iglewicz & Hoaglin)
    """
    candidates = [(k, n) for k, n in counter.items() if n >= min_count]
    if not candidates:
        return []

    values = sorted(counter.values())
    if len(values) < t['outlier_min_population']:
        return candidates

    median = values[len(values) // 2]
    mad = sorted(abs(v - median) for v in values)[len(values) // 2]

    if mad == 0:
        return [(k, n) for k, n in candidates if n > median]

    return [
        (k, n) for k, n in candidates
        if 0.6745 * (n - median) / mad >= t['outlier_z']
    ]


def _volume_peaks(by_hour, sigma, min_hours):
    counts = [c for h, c in by_hour.items() if h]
    if len(counts) < min_hours:
        return []

    mean = sum(counts) / len(counts)
    std = math.sqrt(sum((c - mean) ** 2 for c in counts) / len(counts))
    if std == 0:
        return []

    limit = mean + sigma * std
    return [
        (hour, count, mean, std)
        for hour, count in by_hour.items()
        if hour and count > limit
    ]


def find_patterns(report, thresholds=None):
    """Aplica as regras de base e devolve a lista de padrões suspeitos."""
    t = dict(DEFAULT_THRESHOLDS, **(thresholds or {}))
    full = report['_full']
    auth = report['auth']
    crypto = report['crypto']
    patterns = []

    # 1. Número incomum de tentativas de autenticação (por IP).
    for ip, n in _outliers(full['auth_fail_by_ip'], t['auth_failures_per_ip'], t):
        patterns.append(_pattern(
            'AUTH_ATTEMPTS', ip,
            f'{n} falhas de login a partir do IP {ip}',
            _score(n, t['auth_failures_per_ip']),
            {'failures': n, 'threshold': t['auth_failures_per_ip']},
        ))

    # 1b. Mesmo usuário atacado de vários IPs (ataque distribuído).
    for user, n in _outliers(full['auth_fail_by_user'], t['auth_failures_per_user'], t):
        n_ips = auth['ips_per_user'].get(user, 0)
        if n_ips >= t['auth_ips_per_user']:
            patterns.append(_pattern(
                'AUTH_ATTEMPTS', user,
                f'{n} falhas de login contra "{user}" vindas de {n_ips} IPs',
                _score(n, t['auth_failures_per_user']),
                {'failures': n, 'distinct_ips': n_ips},
            ))

    # 2. Frequência elevada de falhas de descriptografia.
    attempts = crypto['decrypt'] + crypto['decrypt_failures']
    rate = crypto['decrypt_failure_rate']
    if attempts >= t['decrypt_min_attempts'] and rate >= t['decrypt_failure_rate']:
        patterns.append(_pattern(
            'DECRYPT_FAILURES', 'global',
            f'{rate:.0%} das decifragens falharam ({crypto["decrypt_failures"]}/{attempts})',
            _score(rate, t['decrypt_failure_rate']),
            {'rate': round(rate, 4), 'attempts': attempts,
             'reasons': crypto['failure_reasons']},
        ))
    for ip, n in _outliers(full['crypto_fail_by_ip'], t['decrypt_failures_per_ip'], t):
        patterns.append(_pattern(
            'DECRYPT_FAILURES', ip,
            f'{n} falhas de decifragem a partir do IP {ip}',
            _score(n, t['decrypt_failures_per_ip']),
            {'failures': n},
        ))

    # 3. Alterações inesperadas em arquivos.
    for ip, n in full['file_suspicious_by_ip'].items():
        patterns.append(_pattern(
            'FILE_CHANGES', ip,
            f'{n} acessos a arquivo com caminho suspeito (IP {ip})',
            _score(n, 1), {'suspicious_paths': n},
        ))
    for user, n in _outliers(full['file_events_by_user'], t['file_events_per_user'], t):
        patterns.append(_pattern(
            'FILE_CHANGES', user,
            f'{n} operações de arquivo pelo usuário "{user}"',
            _score(n, t['file_events_per_user']),
            {'file_events': n}, severity='WARNING',
        ))

    # 4. Padrões atípicos de acesso.
    for hp in auth['honeypot']:
        patterns.append(_pattern(
            'ACCESS_PATTERN', hp['user'],
            f'Senha honeypot usada para "{hp["user"]}" (IP {hp["ip"]})',
            1.0, hp, severity='CRITICAL',
        ))
    for user, n in _outliers(full['admin_denied_by_user'], t['admin_denied_per_user'], t):
        patterns.append(_pattern(
            'ACCESS_PATTERN', user,
            f'{n} tentativas de acesso ao painel admin por "{user}"',
            _score(n, t['admin_denied_per_user']),
            {'denied': n},
        ))

    # 5. Geração incomum de eventos (pico horário).
    for hour, count, mean, std in _volume_peaks(
        report['by_hour'], t['volume_sigma'], t['volume_min_hours']
    ):
        patterns.append(_pattern(
            'EVENT_VOLUME', hour,
            f'{count} eventos em {hour}h (média {mean:.0f} ± {std:.0f})',
            round(min(1.0, 0.5 + (count - mean) / (10 * std)), 3),
            {'count': count, 'mean': round(mean, 1), 'std': round(std, 1)},
            severity='WARNING',
        ))

    patterns.sort(key=lambda p: p['score'] or 0, reverse=True)
    return patterns


def store_patterns(patterns, detector='regras'):
    """Grava os padrões encontrados como anomalias. Retorna quantos gravou."""
    from app.bigdata.anomalies import record_anomaly

    for p in patterns:
        record_anomaly(
            p['anomaly_type'],
            p['description'],
            severity=p['severity'],
            score=p['score'],
            subject=p['subject'],
            detector=detector,
            evidence=p['evidence'],
        )
    return len(patterns)
