"""
Armazenamento de senhas com Argon2id + esteganografia (LSB) + honeypot.

Fluxo:
  1. A senha real é transformada em hash Argon2id (salt aleatório de 16 bytes
     gerado a cada hash e embutido no próprio hash codificado).
  2. Esse hash é escondido nos bits menos significativos (LSB) dos canais
     RGB de uma imagem PNG gerada por código.
  3. O PNG é salvo na coluna users.ps_images (BYTEA).
  4. A coluna users.password vira um HONEYPOT: guarda o MD5 de uma senha
     falsa plausível. Quem quebrar esse MD5 e tentar logar com ela é bloqueado
     e gera o evento HONEYPOT_TRIGGERED nos logs de segurança.

Uso pela linha de comando (dentro do container):
  python -m app.stego extract imagem.png   -> mostra o hash escondido
"""

import hashlib
import io
import secrets
import struct
import sys

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from PIL import Image


# Parâmetros padrão do argon2-cffi (perfil RFC 9106 "low memory"):
# Argon2id, t=3, m=64 MiB, p=4, salt de 16 bytes.
_hasher = PasswordHasher()

MAGIC = b'AHS1'          # identifica imagens geradas por este módulo
IMAGE_SIZE = 128         # 128x128x3 bits = 6144 bytes de capacidade


# ---------------------------------------------------------------- hash

def hash_password(password):
    """Retorna o hash Argon2id (com salt) da senha."""
    return _hasher.hash(password)


# ---------------------------------------------------------------- imagem de capa

def _generate_cover(size=IMAGE_SIZE):
    """
    Gera um avatar abstrato aleatório: gradiente entre duas cores + blocos
    simétricos (estilo identicon) + ruído leve, para que a alteração dos LSBs
    não crie padrões visíveis.
    """
    rnd = secrets.SystemRandom()

    c1 = [rnd.randint(40, 215) for _ in range(3)]
    c2 = [rnd.randint(40, 215) for _ in range(3)]
    accent = [rnd.randint(0, 255) for _ in range(3)]

    # Grade 5x5 espelhada horizontalmente (identicon)
    grid = 5
    cells = [[rnd.random() < 0.5 for _ in range(3)] for _ in range(grid)]
    cell = size // grid

    img = Image.new('RGB', (size, size))
    px = img.load()

    for y in range(size):
        t = y / (size - 1)
        base = [int(c1[i] * (1 - t) + c2[i] * t) for i in range(3)]
        gy = min(y // cell, grid - 1)

        for x in range(size):
            gx = min(x // cell, grid - 1)
            col = gx if gx < 3 else grid - 1 - gx
            color = accent if cells[gy][col] else base
            px[x, y] = tuple(
                max(0, min(255, color[i] + rnd.randint(-6, 6)))
                for i in range(3)
            )

    return img


# ---------------------------------------------------------------- esteganografia LSB

def _embed(img, payload):
    """Esconde MAGIC + tamanho (4 bytes) + payload nos LSBs dos canais RGB."""
    data = MAGIC + struct.pack('>I', len(payload)) + payload
    bits = ''.join(f'{byte:08b}' for byte in data)

    flat = list(img.getdata())
    capacity = len(flat) * 3
    if len(bits) > capacity:
        raise ValueError('Payload maior que a capacidade da imagem.')

    channels = [c for pixel in flat for c in pixel]
    for i, bit in enumerate(bits):
        channels[i] = (channels[i] & ~1) | int(bit)

    out = Image.new('RGB', img.size)
    out.putdata([tuple(channels[i:i + 3]) for i in range(0, len(channels), 3)])
    return out


def _read_bytes(channels, start, count):
    out = bytearray()
    for b in range(count):
        byte = 0
        for i in range(8):
            byte = (byte << 1) | (channels[start + b * 8 + i] & 1)
        out.append(byte)
    return bytes(out)


def extract_payload(png_bytes):
    """Extrai o conteúdo escondido na imagem. Retorna None se não houver."""
    img = Image.open(io.BytesIO(bytes(png_bytes))).convert('RGB')
    channels = [c for pixel in img.getdata() for c in pixel]

    header_len = len(MAGIC) + 4
    header = _read_bytes(channels, 0, header_len)
    if header[:len(MAGIC)] != MAGIC:
        return None

    (length,) = struct.unpack('>I', header[len(MAGIC):])
    if (header_len + length) * 8 > len(channels):
        return None

    return _read_bytes(channels, header_len * 8, length)


# ---------------------------------------------------------------- API usada pelas rotas

def create_password_image(password):
    """Gera o PNG (bytes) com o hash Argon2id da senha escondido."""
    stego = _embed(_generate_cover(), hash_password(password).encode())

    buf = io.BytesIO()
    stego.save(buf, format='PNG')   # PNG é sem perdas: preserva os LSBs
    return buf.getvalue()


def verify_password_image(png_bytes, password):
    """Extrai o hash da imagem e verifica a senha com Argon2id."""
    if not png_bytes:
        return False

    try:
        payload = extract_payload(png_bytes)
        if payload is None:
            return False
        return _hasher.verify(payload.decode(), password)
    except (VerificationError, InvalidHashError, ValueError, OSError):
        return False


# ---------------------------------------------------------------- honeypot

_DECOY_WORDS = [
    'academic', 'Academic', 'aluno', 'Aluno', 'portal', 'Portal',
    'senha', 'Senha', 'mudar', 'Mudar', 'cesar', 'Cesar',
    'brasil', 'Brasil', 'recife', 'Recife', 'faculdade', 'Faculdade',
]
_DECOY_SUFFIX = ['', '@', '!', '#']


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def generate_decoy_password(real_password=None):
    """
    Cria uma senha falsa plausível (palavra + dígitos), propositalmente fácil
    de quebrar a partir do MD5, para atrair o atacante para o honeypot.
    """
    while True:
        decoy = (
            secrets.choice(_DECOY_WORDS)
            + secrets.choice(_DECOY_SUFFIX)
            + str(secrets.randbelow(9000) + 1000)
        )
        if decoy != real_password:
            return decoy


def build_credentials(password):
    """
    Retorna (honeypot_md5, ps_image_png) para gravar em
    users.password e users.ps_images.
    """
    return (
        md5(generate_decoy_password(password)),
        create_password_image(password),
    )


# ---------------------------------------------------------------- CLI

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'extract':
        with open(sys.argv[2], 'rb') as f:
            data = extract_payload(f.read())
        print(data.decode() if data else 'Nenhum dado escondido encontrado.')
    else:
        print('Uso: python -m app.stego extract <imagem.png>')
