"""
Utilitários compartilhados pela suíte de ataques à AcademicCipher.

Inclui o "bootstrap" de path (para rodar os scripts tanto via
`python -m scripts.ataques.x` quanto `python scripts/ataques/x.py`) e
funções de métrica (contagem de bits, distância de Hamming, entropia).
"""

import os
import sys

# Bootstrap de path: garante que a raiz do projeto (onde fica `app/`) e esta
# própria pasta estejam importáveis, independentemente de como o script roda.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..'))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import math
from collections import Counter


def popcount(data):
    """Número de bits 1 em uma sequência de bytes."""
    return bin(int.from_bytes(data, 'big')).count('1')


def hamming(a, b):
    """Distância de Hamming (bits diferentes) entre dois blocos de bytes."""
    return popcount(bytes(x ^ y for x, y in zip(a, b)))


def flip_bit(data, bit_index):
    """Retorna uma cópia de `data` com o bit `bit_index` invertido."""
    out = bytearray(data)
    out[bit_index // 8] ^= (1 << (bit_index % 8))
    return bytes(out)


def shannon_entropy(data):
    """Entropia de Shannon em bits/byte (ideal = 8.0 para bytes uniformes)."""
    if not data:
        return 0.0

    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def chi_square_uniform_bytes(data):
    """
    Estatística qui-quadrado da distribuição de bytes contra a uniforme.

    Para 256 categorias há 255 graus de liberdade. Valores próximos de 255
    indicam distribuição uniforme (bom para texto cifrado). Valores muito
    altos indicam viés (padrão explorável).
    """
    n = len(data)
    if n == 0:
        return 0.0

    expected = n / 256.0
    counts = Counter(data)
    chi = 0.0
    for b in range(256):
        obs = counts.get(b, 0)
        chi += (obs - expected) ** 2 / expected
    return chi


def count_repeated_blocks(data, block_size=16):
    """Quantos blocos de `block_size` bytes se repetem (ECB vazaria padrões)."""
    blocks = [
        bytes(data[i:i + block_size])
        for i in range(0, len(data) - block_size + 1, block_size)
    ]
    counts = Counter(blocks)
    return sum(c - 1 for c in counts.values() if c > 1), len(blocks)


def human_time(seconds):
    """Formata uma duração em segundos de forma legível (até eras)."""
    if seconds < 1e-3:
        return f'{seconds * 1e6:.1f} µs'
    if seconds < 1:
        return f'{seconds * 1e3:.1f} ms'
    units = [
        ('segundos', 60),
        ('minutos', 60),
        ('horas', 24),
        ('dias', 365),
        ('anos', 1000),
        ('milênios', 1e6),
        ('milhões de anos', 1e3),
        ('bilhões de anos', 1e100),
    ]
    value = seconds
    name = 'segundos'
    for unit_name, factor in units:
        if value < factor:
            name = unit_name
            break
        value /= factor
        name = unit_name
    return f'{value:,.2f} {name}'


def header(title):
    """Imprime um cabeçalho de seção padronizado."""
    print()
    print('=' * 70)
    print(title)
    print('=' * 70)
