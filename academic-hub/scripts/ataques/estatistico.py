"""
ATAQUE ESTATÍSTICO à AcademicCipher (Projeto - Parte 3 e 4).

Testa se a saída cifrada revela padrões do texto claro. Um bom sistema
simétrico produz texto cifrado estatisticamente indistinguível de ruído
aleatório: distribuição de bytes uniforme, entropia máxima e sem blocos
repetidos (mesmo quando o texto claro é extremamente repetitivo).

Métricas:
  - Entropia de Shannon (bits/byte) do texto claro vs cifrado (ideal 8.0).
  - Qui-quadrado da distribuição de bytes do cifrado (ideal ~255).
  - Blocos de 16 bytes repetidos no cifrado (ideal 0 — expõe modo ECB).
  - Frequência dos bytes mais comuns antes e depois.
"""

import os
from collections import Counter

try:
    from .utils import (
        header, shannon_entropy, chi_square_uniform_bytes,
        count_repeated_blocks,
    )
except ImportError:
    from utils import (
        header, shannon_entropy, chi_square_uniform_bytes,
        count_repeated_blocks,
    )

from app.crypto import encrypt


def _corpo_cifrado(envelope):
    """Remove o cabeçalho (magic+salt+iv = 36 bytes) e devolve só o cifrado."""
    return envelope[36:]


def analisa(nome, plaintext):
    key = b'chave-estatistico-teste'
    envelope = encrypt(plaintext, key)
    cipher = _corpo_cifrado(envelope)

    ent_p = shannon_entropy(plaintext)
    ent_c = shannon_entropy(cipher)
    chi = chi_square_uniform_bytes(cipher)
    repetidos, total_blocos = count_repeated_blocks(cipher)

    top_p = Counter(plaintext).most_common(3)
    top_c = Counter(cipher).most_common(3)

    print(f'\n  [{nome}]  ({len(plaintext)} bytes)')
    print(f'    entropia texto claro : {ent_p:.3f} bits/byte')
    print(f'    entropia cifrado     : {ent_c:.3f} bits/byte   (ideal 8.000)')
    print(f'    qui-quadrado cifrado : {chi:.1f}   (ideal ~255; alto = viés)')
    print(f'    blocos repetidos     : {repetidos}/{total_blocos}   (ideal 0)')
    print(f'    bytes + comuns claro : {[(b, n) for b, n in top_p]}')
    print(f'    bytes + comuns cifr. : {[(b, n) for b, n in top_c]}')

    return {
        'nome': nome,
        'ent_plain': ent_p,
        'ent_cipher': ent_c,
        'chi': chi,
        'repetidos': repetidos,
        'blocos': total_blocos,
    }


def main():
    header('ATAQUE ESTATÍSTICO — AcademicCipher')

    casos = {
        'Texto repetitivo (50k "A")': b'A' * 50000,
        'Texto natural repetido': (b'o rato roeu a roupa do rei de roma. ' * 1400),
        'Padrao de blocos iguais': (b'BLOCO-DE-16-BYTE' * 3000),
        'Dados aleatorios (controle)': os.urandom(48000),
    }

    resultados = []
    for nome, pt in casos.items():
        resultados.append(analisa(nome, pt))

    # veredito agregado (ignora o controle aleatório)
    cifrados = [r for r in resultados if 'aleatorio' not in r['nome'].lower()]
    ent_ok = all(r['ent_cipher'] > 7.99 for r in cifrados)
    rep_ok = all(r['repetidos'] == 0 for r in cifrados)

    print('\n  Conclusão:')
    print(f'    - Entropia do cifrado ~8.0 mesmo com entrada repetitiva: '
          f'{"SIM" if ent_ok else "NÃO"}')
    print(f'    - Zero blocos repetidos (sem vazamento tipo ECB): '
          f'{"SIM" if rep_ok else "NÃO"}')
    print('    - Frequência de caracteres do cifrado é plana → ataque')
    print(f'      estatístico/por frequência INVIÁVEL: '
          f'{"SIM" if ent_ok and rep_ok else "NÃO"}')

    return resultados


if __name__ == '__main__':
    main()
