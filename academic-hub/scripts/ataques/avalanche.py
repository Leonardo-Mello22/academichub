"""
Medição do EFEITO AVALANCHE da AcademicCipher (Projeto - Parte 4).

Mede quanto a saída muda quando se inverte 1 bit da entrada ou da chave.
Critério de Strict Avalanche: idealmente ~50% dos bits de saída mudam.

Métricas produzidas:
  - Avalanche de texto claro (1 bit no bloco de entrada)
  - Avalanche de chave (1 bit na chave mestra)
  - Avalanche acumulada por rodada (mostra a difusão crescendo)
  - Avalanche no modo CBC (1 bit em mensagem de vários blocos)
"""

import os
import statistics

try:
    from .utils import hamming, flip_bit, header
except ImportError:
    from utils import hamming, flip_bit, header

from app.crypto import (
    encrypt, derive_round_keys, encrypt_block,
    ROUNDS, BLOCK_SIZE,
)
from app.crypto.tables import SBOX, BIT_PERM, permute_bits


BITS = BLOCK_SIZE * 8


def _encrypt_block_nrounds(block, round_keys, nrounds):
    """Variante de encrypt_block que para após `nrounds` rodadas (p/ análise)."""
    state = bytearray(b ^ k for b, k in zip(block, round_keys[0]))
    for r in range(1, nrounds + 1):
        for i in range(BLOCK_SIZE):
            state[i] = SBOX[state[i]]
        state = bytearray(permute_bits(state, BIT_PERM))
        rk = round_keys[r]
        for i in range(BLOCK_SIZE):
            state[i] ^= rk[i]
    return bytes(state)


def avalanche_plaintext(samples=40):
    """Vira cada bit do texto claro e mede a mudança média na saída."""
    key = b'chave-avalanche-teste'
    salt = os.urandom(16)
    rk = derive_round_keys(key, salt, ROUNDS)

    ratios = []
    for _ in range(samples):
        base = os.urandom(BLOCK_SIZE)
        c0 = encrypt_block(base, rk)
        for bit in range(BITS):
            c1 = encrypt_block(flip_bit(base, bit), rk)
            ratios.append(hamming(c0, c1) / BITS)

    return _summary('Texto claro (1 bit no bloco)', ratios)


def avalanche_key(samples=40):
    """Vira cada bit da chave e mede a mudança média na saída."""
    salt = os.urandom(16)
    ratios = []
    for _ in range(samples):
        base = os.urandom(BLOCK_SIZE)
        key = bytearray(os.urandom(16))
        c0 = encrypt_block(base, derive_round_keys(bytes(key), salt, ROUNDS))
        for bit in range(len(key) * 8):
            k1 = flip_bit(bytes(key), bit)
            c1 = encrypt_block(base, derive_round_keys(k1, salt, ROUNDS))
            ratios.append(hamming(c0, c1) / BITS)

    return _summary('Chave (1 bit na chave mestra)', ratios)


def avalanche_por_rodada(samples=30):
    """Mostra a avalanche acumulada após cada rodada (difusão progressiva)."""
    key = b'chave-avalanche-teste'
    salt = os.urandom(16)
    rk = derive_round_keys(key, salt, ROUNDS)

    print('\n  Avalanche acumulada por rodada (1 bit de entrada):')
    print('  rodada | % bits alterados na saída')
    print('  -------+--------------------------')
    por_rodada = {}
    for nr in range(1, ROUNDS + 1):
        ratios = []
        for _ in range(samples):
            base = os.urandom(BLOCK_SIZE)
            c0 = _encrypt_block_nrounds(base, rk, nr)
            bit = os.urandom(1)[0] % BITS
            c1 = _encrypt_block_nrounds(flip_bit(base, bit), rk, nr)
            ratios.append(hamming(c0, c1) / BITS)
        pct = statistics.mean(ratios) * 100
        por_rodada[nr] = pct
        bar = '#' * int(pct / 2)
        print(f'  {nr:>6} | {pct:5.1f}%  {bar}')

    return por_rodada


def avalanche_cbc(blocks=8):
    """Avalanche no modo CBC completo (salt+IV fixos p/ comparação justa)."""
    key = b'chave-avalanche-teste'
    salt = os.urandom(16)
    iv = os.urandom(16)
    msg = os.urandom(blocks * BLOCK_SIZE)

    c0 = encrypt(msg, key, salt=salt, iv=iv)
    total = 0
    n = 0
    for bit in range(0, len(msg) * 8, 7):          # amostra de bits
        c1 = encrypt(flip_bit(msg, bit), key, salt=salt, iv=iv)
        # compara só o corpo cifrado (ignora cabeçalho magic/salt/iv)
        body0 = c0[len(c0) - len(msg):]
        body1 = c1[len(c1) - len(msg):]
        total += hamming(body0, body1) / (len(msg) * 8)
        n += 1

    pct = (total / n) * 100
    print(f'\n  CBC ({blocks} blocos): mudança média = {pct:.1f}% dos bits')
    return pct


def _summary(nome, ratios):
    media = statistics.mean(ratios) * 100
    desvio = statistics.pstdev(ratios) * 100
    print(f'\n  {nome}')
    print(f'    amostras de bit-flip : {len(ratios)}')
    print(f'    média                : {media:.2f}%   (ideal = 50%)')
    print(f'    desvio-padrão        : {desvio:.2f}%')
    print(f'    mínimo / máximo      : {min(ratios)*100:.1f}% / {max(ratios)*100:.1f}%')
    return {'nome': nome, 'media': media, 'desvio': desvio, 'n': len(ratios)}


def main():
    header('EFEITO AVALANCHE — AcademicCipher')
    r1 = avalanche_plaintext()
    r2 = avalanche_key()
    avalanche_por_rodada()
    cbc = avalanche_cbc()

    print('\n  Conclusão:')
    print(f'    - Avalanche de texto : {r1["media"]:.1f}%  (alvo 50%)')
    print(f'    - Avalanche de chave : {r2["media"]:.1f}%  (alvo 50%)')
    veredito = 'SIM' if 45 <= r1['media'] <= 55 and 45 <= r2['media'] <= 55 else 'PARCIAL'
    print(f'    - Apresenta efeito avalanche? {veredito}')
    return {'texto': r1, 'chave': r2, 'cbc': cbc}


if __name__ == '__main__':
    main()
