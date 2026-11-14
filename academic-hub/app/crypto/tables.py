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


def permute_bits(block, table):
    """
    Aplica uma permutação de bits a um bloco de 16 bytes.

    `table` é BIT_PERM (cifragem) ou INV_BIT_PERM (decifragem). Converte o bloco
    em um inteiro de 128 bits (big-endian, MSB primeiro) e reposiciona cada bit.
    """
    n = int.from_bytes(block, 'big')
    out = 0

    for i in range(BLOCK_BITS):
        bit = (n >> (BLOCK_BITS - 1 - table[i])) & 1
        out |= bit << (BLOCK_BITS - 1 - i)

    return out.to_bytes(BLOCK_SIZE, 'big')


def _self_check():
    """Verificação de sanidade: tabelas são realmente bijetivas/inversíveis."""
    assert sorted(SBOX) == list(range(256))
    assert all(INV_SBOX[SBOX[i]] == i for i in range(256))
    assert sorted(BIT_PERM) == list(range(BLOCK_BITS))
    assert all(INV_BIT_PERM[BIT_PERM[i]] == i for i in range(BLOCK_BITS))


_self_check()
