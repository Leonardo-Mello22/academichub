"""
ATAQUE DE FORÇA BRUTA à AcademicCipher (Projeto - Parte 3).

Duas frentes:
  1. ESPAÇO DE CHAVES (teórico): calcula o tamanho do espaço e o tempo para
     exauri-lo sob diferentes hipóteses de chave e de velocidade do atacante.
  2. EMPÍRICO: mede a vazão real de decifragem desta máquina e executa uma
     força bruta real sobre um espaço PEQUENO (PIN numérico), demonstrando a
     recuperação da chave e extrapolando para espaços maiores.
"""

import itertools
import os
import time

try:
    from .utils import header, human_time
except ImportError:
    from utils import header, human_time

from app.crypto import encrypt, decrypt, DecryptionError


def espaco_de_chaves():
    header('FORÇA BRUTA — Espaço de chaves (teórico)')

    # velocidades hipotéticas do atacante (tentativas/segundo)
    velocidades = {
        'PC comum (1e6/s)': 1e6,
        'GPU (1e9/s)': 1e9,
        'cluster (1e12/s)': 1e12,
    }

    cenarios = {
        'PIN 4 dígitos': 10 ** 4,
        'Senha 6 alfanum. (a-z0-9)': 36 ** 6,
        'Senha 8 alfanum. (a-z0-9)': 36 ** 8,
        'Senha 10 (a-zA-Z0-9)': 62 ** 10,
        'Chave aleatória 128 bits': 2 ** 128,
    }

    for nome, espaco in cenarios.items():
        print(f'\n  {nome}: {espaco:.3e} chaves possíveis')
        for vnome, vps in velocidades.items():
            # tempo médio = metade do espaço / velocidade
            segundos = (espaco / 2) / vps
            print(f'    {vnome:<20} → {human_time(segundos)}')

    return cenarios


def _tenta_chave(envelope, chave):
    try:
        decrypt(envelope, chave)
        return True
    except DecryptionError:
        return False


def vazao_decifragem(amostras=2000):
    """Mede quantas tentativas de decifragem por segundo esta máquina faz."""
    env = encrypt(b'mensagem-alvo-para-benchmark', b'chave-real-123')
    t0 = time.perf_counter()
    for i in range(amostras):
        _tenta_chave(env, str(i).encode())
    dt = time.perf_counter() - t0
    taxa = amostras / dt
    print(f'\n  Vazão real desta máquina: {taxa:,.0f} tentativas/s '
          f'({amostras} em {dt:.2f}s)')
    return taxa


def forca_bruta_real(digitos=4):
    """
    Força bruta REAL sobre uma chave fraca: um PIN numérico de `digitos`.
    Demonstra recuperação da chave e serve de base para extrapolação.
    """
    header('FORÇA BRUTA — Execução real (chave fraca: PIN)')

    segredo = '0042' if digitos == 4 else '1234'[:digitos]
    plaintext = b'informacao confidencial do AcademicHub'
    envelope = encrypt(plaintext, segredo.encode())

    print(f'  Chave secreta (PIN de {digitos} dígitos): oculta')
    print(f'  Espaço: {10**digitos} chaves. Iniciando varredura...')

    t0 = time.perf_counter()
    achou = None
    tentativas = 0
    for tupla in itertools.product('0123456789', repeat=digitos):
        candidato = ''.join(tupla)
        tentativas += 1
        try:
            dec = decrypt(envelope, candidato.encode())
            if dec == plaintext:
                achou = candidato
                break
        except DecryptionError:
            continue
    dt = time.perf_counter() - t0

    print(f'  Chave recuperada: {achou!r} em {tentativas} tentativas '
          f'({dt:.2f}s)')
    print(f'  → PIN fraco quebrado quase instantaneamente.')
    return {'pin': achou, 'tentativas': tentativas, 'tempo': dt}


def extrapolacao(taxa):
    """Usa a vazão real para estimar tempo de quebra de chaves fortes."""
    print('\n  Extrapolação com a vazão REAL desta máquina:')
    for nome, espaco in {
        'Senha 8 alfanum.': 36 ** 8,
        'Chave 128 bits': 2 ** 128,
    }.items():
        segundos = (espaco / 2) / taxa
        print(f'    {nome:<20} → {human_time(segundos)}')


def main():
    espaco_de_chaves()
    taxa = vazao_decifragem()
    res = forca_bruta_real()
    extrapolacao(taxa)

    print('\n  Conclusão:')
    print('    - Chave aleatória de 128 bits: força bruta INVIÁVEL')
    print('      (bilhões de anos mesmo em cluster).')
    print('    - A segurança depende da ENTROPIA da chave: senhas curtas/')
    print('      previsíveis caem em segundos. Daí a geração dinâmica + salt.')
    return res


if __name__ == '__main__':
    main()
