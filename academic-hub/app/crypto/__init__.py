"""
Pacote de criptografia do projeto — AcademicCipher.

Cifra de bloco simétrica autoral (SPN de 128 bits) com geração dinâmica de
chaves, criada para o estudo de efeito avalanche e resistência a ataques
(força bruta, diferencial e estatístico).

API pública:
    from app.crypto import encrypt, decrypt, encrypt_text, decrypt_text
"""

from app.crypto.cipher import (
    encrypt,
    decrypt,
    encrypt_text,
    decrypt_text,
    encrypt_block,
    decrypt_block,
    DecryptionError,
    ROUNDS,
    BLOCK_SIZE,
)
from app.crypto.key_schedule import derive_round_keys

__all__ = [
    'encrypt',
    'decrypt',
    'encrypt_text',
    'decrypt_text',
    'encrypt_block',
    'decrypt_block',
    'derive_round_keys',
    'DecryptionError',
    'ROUNDS',
    'BLOCK_SIZE',
]
