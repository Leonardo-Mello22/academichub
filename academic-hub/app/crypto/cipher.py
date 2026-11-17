"""
AcademicCipher — cifra de bloco simétrica autoral.

Estrutura: rede de substituição-permutação (SPN) de 128 bits.
  Por rodada:  AddRoundKey (XOR)  ->  SubBytes (S-box)  ->  Permutação de bits
  Modo de operação: CBC com IV aleatório e padding PKCS#7.

Propriedades de projeto:
  - Blocos de 128 bits (16 bytes).
  - CONFUSÃO: S-box não-linear em cada byte.
  - DIFUSÃO: permutação de bits espalha cada bit por todo o bloco; o modo CBC
    propaga a difusão entre blocos.
  - Chave dinâmica: subchaves derivadas de chave mestra + salt por mensagem.

Aviso: algoritmo educacional, criado para estudo de ataques e do efeito
avalanche. NÃO use para proteger dados reais.
"""

import os

from app.crypto.tables import (
    SBOX,
    INV_SBOX,
    BIT_PERM,
    INV_BIT_PERM,
    BLOCK_SIZE,
    permute_bits,
)
from app.crypto.key_schedule import derive_round_keys


ROUNDS = 16
SALT_SIZE = 16
IV_SIZE = BLOCK_SIZE
MAGIC = b'ACH1'          # identifica o envelope (AcademicCipher v1)


class DecryptionError(Exception):
    """Falha de decifragem (chave errada, dado corrompido ou adulterado)."""


# Tabelas de tradução (substituição em velocidade de C via bytes.translate).
_SBOX_T = bytes(SBOX)
_INV_SBOX_T = bytes(INV_SBOX)


def _xor16(a, b):
    """XOR de dois blocos de 16 bytes, via inteiro (rápido)."""
    return (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).to_bytes(
        BLOCK_SIZE, 'big'
    )


# ---------------------------------------------------------------------------
# Núcleo: cifragem/decifragem de um único bloco (SPN)
# ---------------------------------------------------------------------------

def encrypt_block(block, round_keys):
    """Cifra um bloco de 16 bytes com a lista de subchaves."""
    state = _xor16(block, round_keys[0])

    for r in range(1, ROUNDS + 1):
        state = state.translate(_SBOX_T)        # SubBytes (confusão)
        state = permute_bits(state, BIT_PERM)   # Permutação de bits (difusão)
        state = _xor16(state, round_keys[r])    # AddRoundKey (XOR)

    return state


def decrypt_block(block, round_keys):
    """Operação inversa de encrypt_block."""
    state = bytes(block)

    for r in range(ROUNDS, 0, -1):
        state = _xor16(state, round_keys[r])
        state = permute_bits(state, INV_BIT_PERM)
        state = state.translate(_INV_SBOX_T)

    return _xor16(state, round_keys[0])


# ---------------------------------------------------------------------------
# Padding PKCS#7
# ---------------------------------------------------------------------------

def _pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _unpad(data):
    if not data or len(data) % BLOCK_SIZE != 0:
        raise DecryptionError('Comprimento de texto cifrado inválido.')

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise DecryptionError('Padding inválido (chave incorreta?).')

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise DecryptionError('Padding inválido (chave incorreta?).')

    return data[:-pad_len]


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Modo CBC + envelope
# ---------------------------------------------------------------------------

def encrypt(plaintext, key, *, salt=None, iv=None):
    """
    Cifra `plaintext` (bytes) com `key` (bytes) no modo CBC.

    Gera salt e IV aleatórios por padrão (saída não-determinística: a mesma
    mensagem cifrada duas vezes produz textos cifrados diferentes).

    Retorna o envelope: MAGIC | salt(16) | iv(16) | ciphertext.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    if salt is None:
        salt = os.urandom(SALT_SIZE)
    if iv is None:
        iv = os.urandom(IV_SIZE)

    round_keys = derive_round_keys(key, salt, ROUNDS)

    data = _pad(plaintext)
    prev = iv
    out = bytearray()

    for off in range(0, len(data), BLOCK_SIZE):
        block = data[off:off + BLOCK_SIZE]
        xored = _xor_bytes(block, prev)
        cipher_block = encrypt_block(xored, round_keys)
        out += cipher_block
        prev = cipher_block

    return MAGIC + salt + iv + bytes(out)


def decrypt(envelope, key):
    """Decifra um envelope produzido por encrypt(). Lança DecryptionError."""
    if isinstance(key, str):
        key = key.encode('utf-8')

    header = len(MAGIC) + SALT_SIZE + IV_SIZE
    if len(envelope) < header:
        raise DecryptionError('Envelope truncado.')
    if envelope[:len(MAGIC)] != MAGIC:
        raise DecryptionError('Envelope não reconhecido (magic inválido).')

    pos = len(MAGIC)
    salt = envelope[pos:pos + SALT_SIZE]
    pos += SALT_SIZE
    iv = envelope[pos:pos + IV_SIZE]
    pos += IV_SIZE
    ciphertext = envelope[pos:]

    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise DecryptionError('Texto cifrado com tamanho inválido.')

    round_keys = derive_round_keys(key, salt, ROUNDS)

    prev = iv
    out = bytearray()

    for off in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[off:off + BLOCK_SIZE]
        decrypted = decrypt_block(block, round_keys)
        out += _xor_bytes(decrypted, prev)
        prev = block

    return _unpad(bytes(out))


# ---------------------------------------------------------------------------
# Helpers de texto
# ---------------------------------------------------------------------------

def encrypt_text(text, key):
    """Cifra uma string e devolve o envelope como texto base64."""
    import base64
    return base64.b64encode(encrypt(text, key)).decode('ascii')


def decrypt_text(token, key):
    """Decifra um envelope base64 e devolve a string original."""
    import base64
    raw = base64.b64decode(token)
    return decrypt(raw, key).decode('utf-8')
