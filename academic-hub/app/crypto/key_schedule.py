"""
Geração dinâmica de chaves de rodada (key schedule) da AcademicCipher.

Requisitos atendidos (Parte 2 do projeto):
  - A chave secreta INFLUENCIA toda a cifragem: cada rodada usa uma subchave
    derivada da chave mestra.
  - A chave NÃO É FIXA: um `salt` aleatório por mensagem é misturado à chave
    mestra, de forma que as subchaves efetivas mudam a cada cifragem, mesmo
    com a mesma chave e o mesmo texto.

O expansor abaixo é autoral (estilo AES simplificado): dobra a chave mestra de
tamanho arbitrário em 16 bytes, mistura o salt, e expande em ROUNDS+1 subchaves
usando S-box (confusão), rotação, constantes de rodada e encadeamento XOR
(difusão dentro da chave).
"""

from app.crypto.tables import SBOX, BLOCK_SIZE


def _normalize_key(master_key):
    """Dobra uma chave de tamanho arbitrário em 16 bytes via XOR cíclico."""
    base = bytearray(BLOCK_SIZE)

    for i, b in enumerate(master_key):
        base[i % BLOCK_SIZE] ^= b

    # Comprimento da chave também influencia o estado inicial.
    base[0] ^= (len(master_key) & 0xFF)

    return base


def derive_round_keys(master_key, salt, rounds):
    """
    Deriva `rounds + 1` subchaves de 16 bytes a partir da chave mestra e do salt.

    Parâmetros:
      master_key: bytes (qualquer tamanho >= 1)
      salt:       bytes aleatórios da mensagem (geração dinâmica)
      rounds:     número de rodadas da cifra

    Retorna: lista de bytes, cada um com 16 posições.
    """
    if not master_key:
        raise ValueError('A chave mestra não pode ser vazia.')

    base = _normalize_key(master_key)

    # Mistura o salt (torna as subchaves dinâmicas por mensagem).
    for i, b in enumerate(salt):
        base[i % BLOCK_SIZE] ^= b

    # Branqueamento inicial com a S-box (confusão).
    for i in range(BLOCK_SIZE):
        base[i] = SBOX[base[i]]

    round_keys = [bytes(base)]
    prev = bytearray(base)

    for r in range(1, rounds + 1):
        new = bytearray(BLOCK_SIZE)

        # Rotaciona a subchave anterior em 1 byte.
        rot = prev[1:] + prev[:1]

        # Constante de rodada: quebra simetrias entre as subchaves.
        rcon = (r * 0x1B) & 0xFF

        for i in range(BLOCK_SIZE):
            new[i] = SBOX[rot[i]] ^ prev[i]
            if i == 0:
                new[i] ^= rcon

        # Encadeamento XOR: cada byte depende do anterior (difusão na chave).
        for i in range(1, BLOCK_SIZE):
            new[i] ^= new[i - 1]

        round_keys.append(bytes(new))
        prev = new

    return round_keys
