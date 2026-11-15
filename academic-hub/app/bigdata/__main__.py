"""
Linha de comando da camada de Big Data.

Uso:
    python -m app.bigdata simular  [--eventos N] [--horas H] [--saida ARQ] [--sem-ataques]
    python -m app.bigdata analisar [ARQ] [--banco] [--horas H] [--registrar] [--json SAIDA]
    python -m app.bigdata cripto   [--operacoes N]

Exemplos:
    # 1 milhão de eventos sintéticos -> análise em fluxo do arquivo
    python -m app.bigdata simular --eventos 1000000
    python -m app.bigdata analisar logs/simulado.jsonl

    # eventos reais do sistema (banco) e gravação das anomalias encontradas
    python -m app.bigdata analisar --banco --registrar

    # operações reais da cifra (gera eventos CRYPTO_* no log)
    python -m app.bigdata cripto --operacoes 50
"""

import argparse
import json
import os
import secrets
import sys

from app.bigdata.analysis import (
    analyze,
    find_patterns,
    iter_db_events,
    iter_jsonl_events,
    public_report,
    store_patterns,
)
from app.bigdata.events import EVENTS_FILE, LOG_DIR


DEFAULT_SIM_FILE = os.path.join(LOG_DIR, 'simulado.jsonl')


# ---------------------------------------------------------------------------
# Saída formatada
# ---------------------------------------------------------------------------

def _print_report(report, patterns):
    proc = report['processing']
    auth = report['auth']
    crypto = report['crypto']

    print(f"\n== Volume processado ==")
    print(f"  eventos         : {report['total']:,}")
    print(f"  tempo           : {proc['seconds']} s "
          f"({proc['events_per_second']:,} eventos/s)")
    print(f"  por categoria   : {report['by_category']}")
    print(f"  por severidade  : {report['by_severity']}")

    print(f"\n== Autenticação ==")
    print(f"  sucessos/falhas : {auth['successes']:,} / {auth['failures']:,}")
    print(f"  top IPs (falha) : {auth['top_failure_ips'][:5]}")
    print(f"  top usuários    : {auth['top_failure_users'][:5]}")
    print(f"  honeypot        : {auth['honeypot_total']}")

    print(f"\n== Operações criptográficas ==")
    print(f"  cifragens       : {crypto['encrypt']:,}")
    print(f"  decifragens     : {crypto['decrypt']:,}")
    print(f"  falhas          : {crypto['decrypt_failures']:,} "
          f"({crypto['decrypt_failure_rate']:.2%})")
    print(f"  bytes           : {crypto['bytes_processed']:,}")
    print(f"  duração média   : {crypto['avg_duration_ms']:.3f} ms")

    print(f"\n== Padrões suspeitos ({len(patterns)}) ==")
    for p in patterns:
        print(f"  [{p['severity']:<8}] {p['anomaly_type']:<16} "
              f"score={p['score']:.2f}  {p['description']}")


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

def cmd_simular(args):
    from app.bigdata.simulation import generate

    print(f'Gerando {args.eventos:,} eventos em {args.saida} ...')
    total = generate(
        args.saida,
        n_events=args.eventos,
        hours=args.horas,
        with_attacks=not args.sem_ataques,
    )
    size_mb = os.path.getsize(args.saida) / 1_048_576
    print(f'{total:,} eventos gravados ({size_mb:.1f} MB).')
    return 0


def cmd_analisar(args):
    if args.banco:
        print(f'Analisando eventos do banco'
              f'{f" (últimas {args.horas}h)" if args.horas else ""} ...')
        events = iter_db_events(window_hours=args.horas)
    else:
        path = args.arquivo or EVENTS_FILE
        if not os.path.exists(path):
            print(f'Arquivo não encontrado: {path}', file=sys.stderr)
            return 1
        print(f'Analisando {path} ...')
        events = iter_jsonl_events(path)

    report = analyze(events)
    patterns = find_patterns(report)
    _print_report(report, patterns)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump({'report': public_report(report), 'patterns': patterns},
                      fh, ensure_ascii=False, indent=2, default=str)
        print(f'\nRelatório JSON salvo em {args.json}')

    if args.registrar:
        n = store_patterns(patterns)
        print(f'\n{n} anomalias registradas (tabela anomaly_events).')
    return 0


def cmd_cripto(args):
    """Executa operações reais da cifra, incluindo falhas propositais."""
    from app import crypto
    from app.bigdata.crypto_ops import decrypt_text, encrypt_text

    key = secrets.token_hex(16)
    ok = fail = 0

    for i in range(args.operacoes):
        token = encrypt_text(f'mensagem de teste #{i}', key, context='cli-demo')

        # ~1 em cada 5 decifragens usa a chave errada.
        use_key = key if i % 5 else 'chave-errada'
        try:
            decrypt_text(token, use_key, context='cli-demo')
            ok += 1
        except crypto.DecryptionError:
            fail += 1

    print(f'{args.operacoes} cifragens, {ok} decifragens ok, {fail} falhas.')
    print(f'Eventos CRYPTO_* gravados em {EVENTS_FILE}')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m app.bigdata',
        description='Coleta, simulação e análise de eventos de segurança.',
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('simular', help='gera eventos sintéticos em JSONL')
    p.add_argument('--eventos', type=int, default=100_000)
    p.add_argument('--horas', type=int, default=72)
    p.add_argument('--saida', default=DEFAULT_SIM_FILE)
    p.add_argument('--sem-ataques', action='store_true')
    p.set_defaults(func=cmd_simular)

    p = sub.add_parser('analisar', help='analisa padrões nos eventos')
    p.add_argument('arquivo', nargs='?', help=f'JSONL (padrão: {EVENTS_FILE})')
    p.add_argument('--banco', action='store_true', help='lê do PostgreSQL')
    p.add_argument('--horas', type=int, help='janela de tempo (só --banco)')
    p.add_argument('--registrar', action='store_true',
                   help='grava os padrões encontrados como anomalias')
    p.add_argument('--json', help='salva o relatório completo em JSON')
    p.set_defaults(func=cmd_analisar)

    p = sub.add_parser('cripto', help='executa operações reais da cifra com log')
    p.add_argument('--operacoes', type=int, default=20)
    p.set_defaults(func=cmd_cripto)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
