"""
Tabelas de substituição (S-box) e permutação de bits da cifra AcademicCipher.

Estas tabelas são a base da CONFUSÃO (S-box) e da DIFUSÃO (permutação de bits)
do algoritmo. Elas são geradas de forma determinística a partir de sementes
fixas, de modo que cifragem e decifragem usem sempre as mesmas tabelas (e seus
inversos), independente da máquina ou execução.

Importante: as sementes abaixo definem a ESTRUTURA pública do algoritmo (como
uma constante de projeto, igual às tabelas fixas do AES). O segredo do sistema
está na CHAVE, não nestas tabelas — ver app/crypto/key_schedule.py.
"""

import random


BLOCK_SIZE = 16          # bytes por bloco (128 bits)
BLOCK_BITS = BLOCK_SIZE * 8

# Sementes fixas de projeto (definem S-box e permutação).
_SBOX_SEED = 0xACADE31C
_PERM_SEED = 0x5EC0DE42


def _build_sbox(seed):
    """
    Gera uma S-box bijetiva de 8 bits (permutação de 0..255) e seu inverso.

    Usa um embaralhamento de Fisher-Yates com PRNG semeado, garantindo uma
    caixa de substituição reversível e de aparência aleatória (boa confusão).
    """
    rng = random.Random(seed)
    values = list(range(256))
    rng.shuffle(values)

    sbox = values
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i

    return sbox, inv


def _build_bit_permutation(seed):
    """
    Gera uma permutação dos 128 bits do bloco e sua inversa.

    Semântica: bit de saída i recebe o valor do bit de entrada BIT_PERM[i].
    A inversa desfaz exatamente esse remapeamento. Espalhar bits por todo o
    bloco é o que produz a DIFUSÃO entre as rodadas.
    """
    rng = random.Random(seed)
    perm = list(range(BLOCK_BITS))
    rng.shuffle(perm)

    inv = [0] * BLOCK_BITS
    for i, p in enumerate(perm):
        inv[p] = i

    return perm, inv


SBOX, INV_SBOX = _build_sbox(_SBOX_SEED)
BIT_PERM, INV_BIT_PERM = _build_bit_permutation(_PERM_SEED)


def _build_perm_lookup(table):
    """
    Pré-computa a permutação como tabela por byte (16 x 256 valores de 128 bits).

    Mantém exatamente a mesma semântica de `out_i = in_{table[i]}`, mas troca o
    laço de 128 bits por 16 buscas de tabela — muito mais rápido em Python puro,
    sem alterar o resultado (cifragem e decifragem continuam compatíveis).
    """
    # posição de saída de cada bit de entrada j (índice i tal que table[i] == j)
    pos_out = [0] * BLOCK_BITS
    for i, j in enumerate(table):
        pos_out[j] = i

    lookup = []
    for p in range(BLOCK_SIZE):
        col = [0] * 256
        base = p * 8
        for v in range(256):
            acc = 0
            for b in range(8):
                if (v >> (7 - b)) & 1:
                    acc |= 1 << (BLOCK_BITS - 1 - pos_out[base + b])
            col[v] = acc
        lookup.append(col)
    return lookup


_PERM_CACHE = {}


def permute_bits(block, table):
    """
    Aplica uma permutação de bits a um bloco de 16 bytes.

    `table` é BIT_PERM (cifragem) ou INV_BIT_PERM (decifragem). Usa uma tabela
    pré-computada (cacheada por tabela) para reposicionar os 128 bits.
    """
    lookup = _PERM_CACHE.get(id(table))
    if lookup is None:
        lookup = _build_perm_lookup(table)
        _PERM_CACHE[id(table)] = lookup

    acc = 0
    for p in range(BLOCK_SIZE):
        acc |= lookup[p][block[p]]

    return acc.to_bytes(BLOCK_SIZE, 'big')


def _self_check():
    """Verificação de sanidade: tabelas são realmente bijetivas/inversíveis."""
    assert sorted(SBOX) == list(range(256))
    assert all(INV_SBOX[SBOX[i]] == i for i in range(256))
    assert sorted(BIT_PERM) == list(range(BLOCK_BITS))
    assert all(INV_BIT_PERM[BIT_PERM[i]] == i for i in range(BLOCK_BITS))


_self_check()
