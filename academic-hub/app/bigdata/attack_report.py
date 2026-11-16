"""
Lê o relatório da suíte de ataques à AcademicCipher para o dashboard.

Fonte padrão: scripts/ataques/resultados/relatorio_ataques.md
(gerado por `python -m scripts.ataques.run_all`).
"""

from __future__ import annotations

import os
import re
from datetime import datetime


_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
DEFAULT_REPORT_PATH = os.path.join(
    _PROJECT_ROOT, 'scripts', 'ataques', 'resultados', 'relatorio_ataques.md'
)


def _float(match, group=1, default=None):
    if not match:
        return default
    try:
        return float(match.group(group).replace(',', '.'))
    except (TypeError, ValueError):
        return default


def load_attack_report(path=None):
    """
    Devolve um dict estruturado para o dashboard, ou None se o arquivo
    não existir / não puder ser lido.
    """
    path = path or DEFAULT_REPORT_PATH
    if not os.path.exists(path):
        return None

    try:
        text = open(path, encoding='utf-8').read()
    except OSError:
        return None

    generated = None
    m = re.search(r'_Gerado em ([^_]+)_', text)
    if m:
        raw = m.group(1).strip()
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
            try:
                generated = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        if generated is None:
            generated = raw

    avalanche_plain = _float(re.search(
        r'1 bit no texto claro\s*\|\s*([\d.]+)%', text
    ))
    avalanche_key = _float(re.search(
        r'1 bit na chave\s*\|\s*([\d.]+)%', text
    ))
    avalanche_cbc = _float(re.search(
        r'Modo CBC[^\|]*\|\s*([\d.]+)%', text
    ))

    delta_weight = _float(re.search(
        r'Peso médio de Δout:\s*\*\*([\d.]+)\s*/\s*128\*\*', text
    ))
    delta_unique = None
    m = re.search(r'Δout distintos:\s*\*\*(\d+)/(\d+)\*\*', text)
    if m:
        delta_unique = {'unique': int(m.group(1)), 'total': int(m.group(2))}
    delta_prob = _float(re.search(
        r'Prob\. da característica mais provável:\s*\*\*([\d.]+)\*\*', text
    ))
    delta_viable = None
    m = re.search(r'Explorável\?\s*\*\*(SIM|NÃO|NAO)\*\*', text, re.I)
    if m:
        delta_viable = m.group(1).upper().startswith('SIM')

    brute_attempts = None
    m = re.search(r'quebrado em\s*\*\*(\d+)\s*tentativas\*\*', text)
    if m:
        brute_attempts = int(m.group(1))
    brute_time = _float(re.search(
        r'quebrado em\s*\*\*\d+\s*tentativas\*\*\s*\(([\d.]+)s\)', text
    ))

    entropy_rows = []
    for row in re.finditer(
        r'\|\s*([^|]+?)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*(\d+)/(\d+)\s*\|',
        text,
    ):
        name = row.group(1).strip()
        if name.lower().startswith('entrada'):
            continue
        entropy_rows.append({
            'name': name,
            'entropy': float(row.group(2)),
            'chi_square': float(row.group(3)),
            'repeated_blocks': int(row.group(4)),
            'total_blocks': int(row.group(5)),
        })

    conclusion = []
    conc = re.search(r'## 5\. Conclusão\s*(.*)', text, re.S)
    if conc:
        for line in conc.group(1).splitlines():
            line = line.strip()
            if line.startswith('- '):
                conclusion.append(line[2:].strip())

    avalanche_ok = (
        avalanche_plain is not None
        and avalanche_key is not None
        and 45 <= avalanche_plain <= 55
        and 45 <= avalanche_key <= 55
    )

    return {
        'path': path,
        'generated_at': generated,
        'avalanche': {
            'plaintext_pct': avalanche_plain,
            'key_pct': avalanche_key,
            'cbc_pct': avalanche_cbc,
            'ok': avalanche_ok,
        },
        'differential': {
            'mean_weight': delta_weight,
            'unique': delta_unique,
            'top_prob': delta_prob,
            'viable': delta_viable,
        },
        'brute_force': {
            'pin_attempts': brute_attempts,
            'pin_seconds': brute_time,
            'strong_key': 'inviável',
        },
        'statistical': {
            'rows': entropy_rows,
            'avg_entropy': (
                round(
                    sum(r['entropy'] for r in entropy_rows) / len(entropy_rows),
                    3,
                )
                if entropy_rows else None
            ),
            'any_repeated': any(r['repeated_blocks'] > 0 for r in entropy_rows),
        },
        'conclusion': conclusion,
    }


def charts_payload(report, patterns, ia_patterns, anomaly_stats_data):
    """Monta o JSON consumido pelo Chart.js no template."""
    by_hour = report.get('by_hour') or {}
    # Ordena e limita a últimas 48 buckets para o gráfico não ficar ilegível.
    hour_items = sorted(by_hour.items())[-48:]
    hour_labels = [h[11:] if len(h) >= 13 else h for h, _ in hour_items]
    hour_values = [n for _, n in hour_items]

    by_category = report.get('by_category') or {}
    by_type = report.get('by_type') or {}
    type_items = list(by_type.items())[:12]

    auth = report.get('auth') or {}
    fail_ips = auth.get('top_failure_ips') or []
    crypto = report.get('crypto') or {}

    pattern_counts = {}
    for p in (patterns or []) + (ia_patterns or []):
        t = p.get('anomaly_type') or 'OTHER'
        pattern_counts[t] = pattern_counts.get(t, 0) + 1

    open_by_type = (anomaly_stats_data or {}).get('by_type') or {}

    return {
        'by_hour': {'labels': hour_labels, 'values': hour_values},
        'by_category': {
            'labels': list(by_category.keys()),
            'values': list(by_category.values()),
        },
        'by_type': {
            'labels': [k for k, _ in type_items],
            'values': [v for _, v in type_items],
        },
        'auth_fail_ips': {
            'labels': [ip for ip, _ in fail_ips[:8]],
            'values': [n for _, n in fail_ips[:8]],
        },
        'crypto': {
            'labels': ['Cifrar', 'Decifrar OK', 'Falhas'],
            'values': [
                crypto.get('encrypt', 0),
                crypto.get('decrypt', 0),
                crypto.get('decrypt_failures', 0),
            ],
        },
        'patterns_window': {
            'labels': list(pattern_counts.keys()),
            'values': list(pattern_counts.values()),
        },
        'anomalies_open': {
            'labels': list(open_by_type.keys()),
            'values': list(open_by_type.values()),
        },
    }
