"""
Linha de comando da camada de Big Data.

Uso:
    python -m app.bigdata simular  [--eventos N] [--horas H] [--saida ARQ] [--sem-ataques]
    python -m app.bigdata analisar [ARQ] [--banco] [--horas H] [--registrar] [--ia] [--json SAIDA]
    python -m app.bigdata cripto   [--operacoes N]
    python -m app.bigdata ia treinar   --arquivo ARQ [--modelo PATH]
    python -m app.bigdata ia detectar  [--arquivo ARQ|--banco] [--modelo PATH] [--registrar]
    python -m app.bigdata ia pipeline  [--eventos N] [--registrar]

Exemplos:
    python -m app.bigdata simular --eventos 1000000
    python -m app.bigdata analisar logs/simulado.jsonl
    python -m app.bigdata analisar --banco --registrar --ia
    python -m app.bigdata cripto --operacoes 50

    python -m app.bigdata simular --sem-ataques --saida logs/normal.jsonl
    python -m app.bigdata ia treinar --arquivo logs/normal.jsonl
    python -m app.bigdata simular --saida logs/ataques.jsonl
    python -m app.bigdata ia detectar --arquivo logs/ataques.jsonl --registrar

    python -m app.bigdata ia pipeline --eventos 50000 --registrar
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
from app.bigdata.ia import DEFAULT_MODEL_PATH


DEFAULT_SIM_FILE = os.path.join(LOG_DIR, 'simulado.jsonl')
DEFAULT_NORMAL_FILE = os.path.join(LOG_DIR, 'normal.jsonl')
DEFAULT_ATTACK_FILE = os.path.join(LOG_DIR, 'ataques.jsonl')


def _print_report(report, patterns, title='Padrões suspeitos'):
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

    print(f"\n== {title} ({len(patterns)}) ==")
    for p in patterns:
        print(f"  [{p['severity']:<8}] {p['anomaly_type']:<16} "
              f"score={p['score']:.2f}  {p['description']}")


def _print_ia_patterns(patterns):
    print(f"\n== Anomalias IA — Isolation Forest ({len(patterns)}) ==")
    if not patterns:
        print('  (nenhuma)')
        return
    for p in patterns:
        print(f"  [{p['severity']:<8}] {p['anomaly_type']:<16} "
              f"score={p['score']:.2f}  {p['description']}")


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
        events = list(iter_db_events(window_hours=args.horas))
    else:
        path = args.arquivo or EVENTS_FILE
        if not os.path.exists(path):
            print(f'Arquivo não encontrado: {path}', file=sys.stderr)
            return 1
        print(f'Analisando {path} ...')
        events = list(iter_jsonl_events(path))

    report = analyze(events)
    patterns = find_patterns(report)
    _print_report(report, patterns)

    ia_patterns = []
    if args.ia:
        from app.bigdata.ia import detect_anomalies, load_model

        model_path = args.modelo or DEFAULT_MODEL_PATH
        model = None
        if os.path.exists(model_path):
            model = load_model(model_path)
            print(f'\nModelo IA carregado: {model_path}')
        else:
            print('\nModelo IA ausente — Isolation Forest não supervisionado nesta janela.')
        ia_patterns = detect_anomalies(events, model=model)
        _print_ia_patterns(ia_patterns)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(
                {
                    'report': public_report(report),
                    'patterns': patterns,
                    'ia_patterns': ia_patterns,
                },
                fh,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        print(f'\nRelatório JSON salvo em {args.json}')

    if args.registrar:
        n = store_patterns(patterns)
        print(f'\n{n} anomalias (regras) registradas.')
        if args.ia and ia_patterns:
            from app.bigdata.ia import store_ia_patterns

            n_ia = store_ia_patterns(ia_patterns)
            print(f'{n_ia} anomalias (ia) registradas.')
    return 0


def cmd_cripto(args):
    from app import crypto
    from app.bigdata.crypto_ops import decrypt_text, encrypt_text

    key = secrets.token_hex(16)
    ok = fail = 0

    for i in range(args.operacoes):
        token = encrypt_text(f'mensagem de teste #{i}', key, context='cli-demo')
        use_key = key if i % 5 else 'chave-errada'
        try:
            decrypt_text(token, use_key, context='cli-demo')
            ok += 1
        except crypto.DecryptionError:
            fail += 1

    print(f'{args.operacoes} cifragens, {ok} decifragens ok, {fail} falhas.')
    print(f'Eventos CRYPTO_* gravados em {EVENTS_FILE}')
    return 0


def cmd_ia_treinar(args):
    from app.bigdata.ia import save_model, train_model

    if not os.path.exists(args.arquivo):
        print(f'Arquivo não encontrado: {args.arquivo}', file=sys.stderr)
        return 1

    model_path = args.modelo or DEFAULT_MODEL_PATH
    print(f'Treinando Isolation Forest com {args.arquivo} ...')
    model = train_model(
        iter_jsonl_events(args.arquivo),
        contamination=args.contamination,
    )
    path = save_model(model, model_path)
    print(f'Modelo salvo em {path}')
    return 0


def cmd_ia_detectar(args):
    from app.bigdata.ia import detect_anomalies, load_model, store_ia_patterns

    if args.banco:
        events = list(iter_db_events(window_hours=args.horas))
        print(f'Detectando no banco'
              f'{f" (últimas {args.horas}h)" if args.horas else ""} ...')
    else:
        if not os.path.exists(args.arquivo):
            print(f'Arquivo não encontrado: {args.arquivo}', file=sys.stderr)
            return 1
        print(f'Detectando em {args.arquivo} ...')
        events = list(iter_jsonl_events(args.arquivo))

    model_path = args.modelo or DEFAULT_MODEL_PATH
    model = None
    if os.path.exists(model_path):
        model = load_model(model_path)
        print(f'Modelo: {model_path}')
    else:
        print('Modelo ausente — modo não supervisionado (fit na própria janela).')

    patterns = detect_anomalies(
        events, model=model, contamination=args.contamination,
    )
    _print_ia_patterns(patterns)
    tipos = sorted({p['anomaly_type'] for p in patterns})
    print(f'\nTipos encontrados: {tipos or "—"}')

    if args.registrar and patterns:
        n = store_ia_patterns(patterns)
        print(f'{n} anomalias (ia) registradas na tabela anomaly_events.')
    return 0


def cmd_ia_pipeline(args):
    from app.bigdata.ia import (
        detect_anomalies,
        load_model,
        save_model,
        store_ia_patterns,
        train_model,
    )
    from app.bigdata.simulation import generate

    model_path = args.modelo or DEFAULT_MODEL_PATH

    print(f'[1/4] Gerando tráfego normal ({args.eventos:,}) → {args.normal}')
    generate(args.normal, n_events=args.eventos, hours=args.horas, with_attacks=False)

    print('[2/4] Treinando Isolation Forest ...')
    model = train_model(
        iter_jsonl_events(args.normal),
        contamination=args.contamination,
    )
    path = save_model(model, model_path)
    print(f'       Modelo: {path}')

    print(f'[3/4] Gerando tráfego com ataques ({args.eventos:,}) → {args.ataques}')
    generate(args.ataques, n_events=args.eventos, hours=args.horas, with_attacks=True)

    print('[4/4] Detectando anomalias ...')
    patterns = detect_anomalies(
        iter_jsonl_events(args.ataques),
        model=load_model(path),
        contamination=args.contamination,
    )
    _print_ia_patterns(patterns)
    tipos = sorted({p['anomaly_type'] for p in patterns})
    print(f'\nTipos encontrados: {tipos or "—"}')

    if args.registrar and patterns:
        n = store_ia_patterns(patterns)
        print(f'{n} anomalias (ia) registradas.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m app.bigdata',
        description='Coleta, simulação, análise e IA de anomalias.',
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
    p.add_argument('--banco', action='store_true')
    p.add_argument('--horas', type=int)
    p.add_argument('--registrar', action='store_true')
    p.add_argument('--json', help='salva o relatório completo em JSON')
    p.add_argument('--ia', action='store_true', help='também roda Isolation Forest')
    p.add_argument('--modelo', default=DEFAULT_MODEL_PATH)
    p.set_defaults(func=cmd_analisar)

    p = sub.add_parser('cripto', help='executa operações reais da cifra com log')
    p.add_argument('--operacoes', type=int, default=20)
    p.set_defaults(func=cmd_cripto)

    pia = sub.add_parser('ia', help='Isolation Forest (camada 5)')
    ia_sub = pia.add_subparsers(dest='ia_cmd', required=True)

    pt = ia_sub.add_parser('treinar', help='treina o modelo no tráfego normal')
    pt.add_argument('--arquivo', required=True)
    pt.add_argument('--modelo', default=DEFAULT_MODEL_PATH)
    pt.add_argument('--contamination', type=float, default=0.03)
    pt.set_defaults(func=cmd_ia_treinar)

    pd = ia_sub.add_parser('detectar', help='detecta anomalias com o modelo')
    pd.add_argument('--arquivo', default=DEFAULT_ATTACK_FILE)
    pd.add_argument('--banco', action='store_true')
    pd.add_argument('--horas', type=int)
    pd.add_argument('--modelo', default=DEFAULT_MODEL_PATH)
    pd.add_argument('--contamination', type=float, default=0.03)
    pd.add_argument('--registrar', action='store_true')
    pd.set_defaults(func=cmd_ia_detectar)

    pp = ia_sub.add_parser(
        'pipeline',
        help='simula normal → treina → simula ataques → detecta',
    )
    pp.add_argument('--eventos', type=int, default=50_000)
    pp.add_argument('--horas', type=int, default=72)
    pp.add_argument('--normal', default=DEFAULT_NORMAL_FILE)
    pp.add_argument('--ataques', default=DEFAULT_ATTACK_FILE)
    pp.add_argument('--modelo', default=DEFAULT_MODEL_PATH)
    pp.add_argument('--contamination', type=float, default=0.03)
    pp.add_argument('--registrar', action='store_true')
    pp.set_defaults(func=cmd_ia_pipeline)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
