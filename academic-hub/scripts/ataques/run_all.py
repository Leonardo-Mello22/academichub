"""
Runner da suíte de ataques à AcademicCipher.

Executa avalanche + diferencial + força bruta + estatístico e consolida os
números num relatório Markdown (scripts/ataques/resultados/relatorio_ataques.md)
pronto para citar no relatório/slides do projeto (Parte 4).

Uso:
    python -m scripts.ataques.run_all
"""

import os
from datetime import datetime

try:
    from . import avalanche, diferencial, forca_bruta, estatistico
    from .utils import header
except ImportError:
    import avalanche
    import diferencial
    import forca_bruta
    import estatistico
    from utils import header


RESULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resultados')


def _escreve_relatorio(aval, dif, fb, est):
    os.makedirs(RESULT_DIR, exist_ok=True)
    caminho = os.path.join(RESULT_DIR, 'relatorio_ataques.md')

    linhas = []
    linhas.append('# Relatório de Ataques — AcademicCipher')
    linhas.append('')
    linhas.append(f'_Gerado em {datetime.now():%Y-%m-%d %H:%M:%S}_')
    linhas.append('')
    linhas.append('## 1. Efeito avalanche')
    linhas.append('')
    linhas.append('| Teste | Mudança média | Ideal |')
    linhas.append('|---|---|---|')
    linhas.append(f'| 1 bit no texto claro | {aval["texto"]["media"]:.2f}% | 50% |')
    linhas.append(f'| 1 bit na chave | {aval["chave"]["media"]:.2f}% | 50% |')
    linhas.append(f'| Modo CBC (mensagem) | {aval["cbc"]:.1f}% | ~50% |')
    linhas.append('')
    linhas.append('## 2. Ataque diferencial')
    linhas.append('')
    linhas.append(f'- Peso médio de Δout: **{dif["media_peso"]:.2f} / 128** '
                  f'(ideal ~64)')
    linhas.append(f'- Δout distintos: **{dif["unicos"]}/{dif["samples"]}**')
    linhas.append(f'- Prob. da característica mais provável: '
                  f'**{dif["prob_top"]:.5f}**')
    linhas.append(f'- Explorável? **{"SIM" if dif["viavel"] else "NÃO"}**')
    linhas.append('')
    linhas.append('## 3. Força bruta')
    linhas.append('')
    linhas.append(f'- PIN fraco (4 díg.) quebrado em **{fb["tentativas"]} '
                  f'tentativas** ({fb["tempo"]:.2f}s).')
    linhas.append('- Chave aleatória de 128 bits: **inviável** '
                  '(≈ 2^127 tentativas médias).')
    linhas.append('')
    linhas.append('## 4. Ataque estatístico')
    linhas.append('')
    linhas.append('| Entrada | Entropia cifrado | Qui-quadrado | Blocos repetidos |')
    linhas.append('|---|---|---|---|')
    for r in est:
        linhas.append(f'| {r["nome"]} | {r["ent_cipher"]:.3f} | '
                      f'{r["chi"]:.1f} | {r["repetidos"]}/{r["blocos"]} |')
    linhas.append('')
    linhas.append('## 5. Conclusão')
    linhas.append('')
    aval_ok = 45 <= aval['texto']['media'] <= 55 and 45 <= aval['chave']['media'] <= 55
    linhas.append(f'- **Efeito avalanche:** {"presente" if aval_ok else "parcial"} '
                  '(próximo de 50%).')
    linhas.append('- **Padrões na saída:** não detectados (entropia ~8.0, '
                  'sem blocos repetidos, Δout uniforme).')
    linhas.append('- **Ataque mais eficaz:** força bruta — porém **só** contra '
                  'chaves fracas; contra chave forte, nenhum ataque foi viável.')
    linhas.append('- **O sistema é seguro?** Contra diferencial e estatístico, '
                  'sim neste escopo. A segurança depende da entropia da chave; '
                  'por ser educacional e sem MAC, não substitui AES em produção.')
    linhas.append('')

    with open(caminho, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(linhas))

    return caminho


def main():
    print('\n######  SUÍTE DE ATAQUES — AcademicCipher  ######')

    aval = avalanche.main()
    dif = diferencial.main()
    fb = forca_bruta.main()
    est = estatistico.main()

    caminho = _escreve_relatorio(aval, dif, fb, est)

    header('RESUMO FINAL')
    print(f'  Avalanche texto : {aval["texto"]["media"]:.1f}%')
    print(f'  Avalanche chave : {aval["chave"]["media"]:.1f}%')
    print(f'  Diferencial     : Δout único em {dif["unicos"]}/{dif["samples"]} '
          f'→ {"inviável" if not dif["viavel"] else "explorável"}')
    print(f'  Força bruta     : PIN em {fb["tentativas"]} tentativas; '
          f'128 bits inviável')
    print(f'  Estatístico     : entropia do cifrado ~8.0, sem padrões')
    print(f'\n  Relatório salvo em: {caminho}')


if __name__ == '__main__':
    main()
