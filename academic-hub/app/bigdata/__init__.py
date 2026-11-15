"""
Camada 4 — Big Data: coleta, armazenamento e análise de eventos de segurança.

Módulos (na ordem do fluxo dos dados):

    events.py      coleta: log_security_event() -> banco + logs/security_events.jsonl
    crypto_ops.py  logs das operações criptográficas (cifra/decifra auditadas)
    anomalies.py   armazenamento das anomalias detectadas (tabela anomaly_events)
    analysis.py    análise de padrões em grande volume (processamento em fluxo)
    simulation.py  gerador de eventos sintéticos para testes de volume
    __main__.py    CLI: python -m app.bigdata {simular,analisar,cripto}

Importe direto do módulo que precisa, por exemplo:

    from app.bigdata.events import log_security_event
    from app.bigdata.crypto_ops import encrypt_text, decrypt_text
    from app.bigdata.anomalies import record_anomaly
"""
