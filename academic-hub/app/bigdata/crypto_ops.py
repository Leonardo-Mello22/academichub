"""
Logs das operações criptográficas (camada 4 — Big Data).

Versões "auditadas" da API da AcademicCipher: fazem exatamente o mesmo que
`app.crypto`, mas registram cada operação como evento de segurança.

    from app.bigdata.crypto_ops import encrypt_text, decrypt_text

    token = encrypt_text('olá', chave, context='messages')
    texto = decrypt_text(token, chave, context='messages')

Eventos gerados:
    CRYPTO_ENCRYPT          (INFO)     cifragem concluída
    CRYPTO_DECRYPT          (INFO)     decifragem concluída
    CRYPTO_DECRYPT_FAILURE  (WARNING)  chave errada / dado corrompido

O que é registrado: tamanhos, nº de blocos, rodadas, duração e um
identificador do envelope (SHA-256 truncado do texto cifrado, que já é
público). NUNCA são registrados a chave nem o texto claro.

O pacote `app.crypto` continua puro (sem log), para que a suíte de ataques
possa cifrar milhões de blocos sem gerar eventos.
"""

import base64
import binascii
import hashlib
import os
import time

from app import crypto
from app.bigdata.events import log_security_event
from app.crypto.cipher import MAGIC

# Chave de laboratório — sobrescrever com CRYPTO_KEY no ambiente.
_DEFAULT_APP_KEY = 'AcademicHub-lab-key-nao-usar-em-producao'


def get_app_key():
    """Chave usada pelas rotas do portal (mensagens, arquivos)."""
    return os.environ.get('CRYPTO_KEY') or _DEFAULT_APP_KEY


def is_encrypted_envelope(data):
    """True se `data` for um envelope AcademicCipher (bytes ou base64)."""
    if not data:
        return False
    if isinstance(data, str):
        try:
            data = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            return False
    return data.startswith(MAGIC)


def _envelope_id(envelope):
    """Identificador curto do envelope, para correlacionar cifra/decifra."""
    return hashlib.sha256(envelope).hexdigest()[:16]


def _as_bytes(value):
    return value.encode('utf-8') if isinstance(value, str) else value


def _log(event_type, message, severity, details):
    log_security_event(event_type, message, severity=severity, details=details)


# ---------------------------------------------------------------------------
# Bytes
# ---------------------------------------------------------------------------

def encrypt(plaintext, key, *, context='app'):
    """crypto.encrypt + evento CRYPTO_ENCRYPT."""
    plaintext = _as_bytes(plaintext)

    start = time.perf_counter()
    envelope = crypto.encrypt(plaintext, key)
    elapsed_ms = (time.perf_counter() - start) * 1000

    _log(
        'CRYPTO_ENCRYPT',
        f'Cifragem concluída ({context})',
        'INFO',
        {
            'context': context,
            'envelope_id': _envelope_id(envelope),
            'plaintext_bytes': len(plaintext),
            'envelope_bytes': len(envelope),
            'blocks': (len(plaintext) // crypto.BLOCK_SIZE) + 1,
            'rounds': crypto.ROUNDS,
            'duration_ms': round(elapsed_ms, 3),
        },
    )
    return envelope


def decrypt(envelope, key, *, context='app'):
    """crypto.decrypt + evento CRYPTO_DECRYPT ou CRYPTO_DECRYPT_FAILURE."""
    details = {
        'context': context,
        'envelope_id': _envelope_id(envelope),
        'envelope_bytes': len(envelope),
        'rounds': crypto.ROUNDS,
    }

    start = time.perf_counter()
    try:
        plaintext = crypto.decrypt(envelope, key)
    except crypto.DecryptionError as exc:
        details['duration_ms'] = round((time.perf_counter() - start) * 1000, 3)
        details['reason'] = str(exc)
        _log(
            'CRYPTO_DECRYPT_FAILURE',
            f'Falha de decifragem ({context})',
            'WARNING',
            details,
        )
        raise

    details['duration_ms'] = round((time.perf_counter() - start) * 1000, 3)
    details['plaintext_bytes'] = len(plaintext)
    _log('CRYPTO_DECRYPT', f'Decifragem concluída ({context})', 'INFO', details)
    return plaintext


# ---------------------------------------------------------------------------
# Texto (base64)
# ---------------------------------------------------------------------------

def encrypt_text(text, key, *, context='app'):
    """Cifra uma string e devolve o envelope em base64 (com log)."""
    return base64.b64encode(encrypt(text, key, context=context)).decode('ascii')


def decrypt_text(token, key, *, context='app'):
    """Decifra um envelope base64 e devolve a string (com log)."""
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError) as exc:
        _log(
            'CRYPTO_DECRYPT_FAILURE',
            f'Falha de decifragem ({context})',
            'WARNING',
            {'context': context, 'reason': f'base64 inválido: {exc}'},
        )
        raise crypto.DecryptionError('Envelope base64 inválido.') from exc

    plaintext = decrypt(raw, key, context=context)
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError as exc:
        # Raro: chave errada que, por acaso, gerou padding válido.
        _log(
            'CRYPTO_DECRYPT_FAILURE',
            f'Falha de decifragem ({context})',
            'WARNING',
            {'context': context, 'envelope_id': _envelope_id(raw),
             'reason': 'texto decifrado não é UTF-8 (chave incorreta?)'},
        )
        raise crypto.DecryptionError('Texto decifrado inválido.') from exc
