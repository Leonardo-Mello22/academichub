"""
Demonstração via linha de comando da AcademicCipher.

Uso:
    python -m app.crypto demo
    python -m app.crypto enc "mensagem"  chave
    python -m app.crypto dec <base64>     chave
"""

import sys

from app.crypto import encrypt_text, decrypt_text, ROUNDS, BLOCK_SIZE


def _demo():
    chave = 'chave-de-demonstracao'
    texto = 'AcademicHub — criptografia simétrica autoral'

    print(f'Parâmetros : bloco={BLOCK_SIZE*8} bits | rodadas={ROUNDS}')
    print(f'Chave      : {chave}')
    print(f'Texto claro: {texto}')

    token = encrypt_text(texto, chave)
    print(f'Cifrado    : {token}')

    recuperado = decrypt_text(token, chave)
    print(f'Decifrado  : {recuperado}')
    print(f'Confere    : {recuperado == texto}')

    print('\n(cifre de novo e veja o cifrado mudar — salt/IV aleatórios)')
    print(f'Cifrado    : {encrypt_text(texto, chave)}')


def main(argv):
    if not argv or argv[0] == 'demo':
        _demo()
        return 0

    cmd = argv[0]

    if cmd == 'enc' and len(argv) == 3:
        print(encrypt_text(argv[1], argv[2]))
        return 0

    if cmd == 'dec' and len(argv) == 3:
        print(decrypt_text(argv[1], argv[2]))
        return 0

    print(__doc__)
    return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
