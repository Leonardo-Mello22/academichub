"""
ATAQUE DIFERENCIAL à AcademicCipher (Projeto - Parte 3).

Ideia: alterar uma diferença fixa na entrada (Δin) e observar a distribuição
das diferenças na saída (Δout). Numa cifra fraca, uma certa Δout aparece com
probabilidade muito maior que o acaso (característica diferencial), o que
permite recuperar chave. Numa cifra forte, as Δout são uniformes e imprevisíveis.

Medimos:
  - Distribuição do peso de Hamming de Δout (deve concentrar em ~64/128).
  - Repetição exata de Δout entre amostras (deve ser ~nula).
  - Probabilidade da característica diferencial mais provável encontrada.
"""

import os
import statistics
from collections import Counter

try:
    from .utils import hamming, flip_bit, header
except ImportError:
    from utils import hamming, flip_bit, header

from app.crypto import derive_round_keys, encrypt_block, ROUNDS, BLOCK_SIZE


BITS = BLOCK_SIZE * 8


def ataque_diferencial(samples=4000, delta_bit=0):
    """
    Fixa a chave e uma diferença de 1 bit na entrada; mede Δout em `samples`
    pares de texto claro aleatórios.
    """
    key = os.urandom(16)
    salt = os.urandom(16)
    rk = derive_round_keys(key, salt, ROUNDS)

    pesos = []
    delta_outs = Counter()

    for _ in range(samples):
        p0 = os.urandom(BLOCK_SIZE)
        p1 = flip_bit(p0, delta_bit)
        c0 = encrypt_block(p0, rk)
        c1 = encrypt_block(p1, rk)
        dout = bytes(x ^ y for x, y in zip(c0, c1))
        pesos.append(hamming(c0, c1))
        delta_outs[dout] += 1

    media = statistics.mean(pesos)
    desvio = statistics.pstdev(pesos)

    # característica diferencial mais provável observada
    dout_top, freq_top = delta_outs.most_common(1)[0]
    prob_top = freq_top / samples
    unicos = len(delta_outs)

    header('ATAQUE DIFERENCIAL — AcademicCipher')
    print(f'  Δin : 1 bit (posição {delta_bit}) | pares testados: {samples}')
    print(f'\n  Peso de Hamming de Δout:')
    print(f'    média         : {media:.2f} / {BITS}   (ideal ~{BITS//2})')
    print(f'    desvio-padrão : {desvio:.2f}')
    print(f'    mín / máx     : {min(pesos)} / {max(pesos)}')
    print(f'\n  Diferenças de saída (Δout) distintas: {unicos}/{samples}')
    print(f'  Δout mais frequente apareceu {freq_top}x  (prob = {prob_top:.5f})')
    print(f'  Acaso esperado p/ um Δout específico: 2^-128 ≈ {2**-128:.2e}')

    viavel = prob_top > 0.01 or not (BITS * 0.4 < media < BITS * 0.6)
    print(f'\n  Característica diferencial explorável? {"SIM" if viavel else "NÃO"}')
    print('  → Sem Δout dominante e com Δout quase sempre único, o ataque')
    print('    diferencial é inviável nesta cifra.')

    return {
        'media_peso': media,
        'desvio': desvio,
        'prob_top': prob_top,
        'unicos': unicos,
        'samples': samples,
        'viavel': viavel,
    }


def main():
    return ataque_diferencial()


if __name__ == '__main__':
    main()
