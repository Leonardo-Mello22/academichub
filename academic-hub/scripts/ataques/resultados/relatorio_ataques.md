# Relatório de Ataques — AcademicCipher

_Gerado em 2026-11-14 15:33:58_

## 1. Efeito avalanche

| Teste | Mudança média | Ideal |
|---|---|---|
| 1 bit no texto claro | 49.98% | 50% |
| 1 bit na chave | 50.05% | 50% |
| Modo CBC (mensagem) | 33.5% | ~50% |

## 2. Ataque diferencial

- Peso médio de Δout: **63.94 / 128** (ideal ~64)
- Δout distintos: **4000/4000**
- Prob. da característica mais provável: **0.00025**
- Explorável? **NÃO**

## 3. Força bruta

- PIN fraco (4 díg.) quebrado em **43 tentativas** (0.04s).
- Chave aleatória de 128 bits: **inviável** (≈ 2^127 tentativas médias).

## 4. Ataque estatístico

| Entrada | Entropia cifrado | Qui-quadrado | Blocos repetidos |
|---|---|---|---|
| Texto repetitivo (50k "A") | 7.996 | 289.7 | 0/3126 |
| Texto natural repetido | 7.996 | 273.7 | 0/3151 |
| Padrao de blocos iguais | 7.996 | 255.5 | 0/3001 |
| Dados aleatorios (controle) | 7.996 | 251.9 | 0/3001 |

## 5. Conclusão

- **Efeito avalanche:** presente (próximo de 50%).
- **Padrões na saída:** não detectados (entropia ~8.0, sem blocos repetidos, Δout uniforme).
- **Ataque mais eficaz:** força bruta — porém **só** contra chaves fracas; contra chave forte, nenhum ataque foi viável.
- **O sistema é seguro?** Contra diferencial e estatístico, sim neste escopo. A segurança depende da entropia da chave; por ser educacional e sem MAC, não substitui AES em produção.
