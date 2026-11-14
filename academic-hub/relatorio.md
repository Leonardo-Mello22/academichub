# Relatório de Progresso — Projeto Cibersegurança (AcademicCipher)

**Projeto:** Sistema Criptográfico + Análise de Ataques
**Base:** AcademicHub (portal acadêmico fictício em Flask + PostgreSQL)
**Atualizado em:** 2026-11-14

Este documento registra **o que já foi feito** e **o que ainda falta**, mapeado
às partes do enunciado da disciplina (Partes 1 a 5).

---

## 1. Visão geral da arquitetura (6 camadas)

| # | Camada | Status |
|---|---|---|
| 1 | Entrada de dados (texto/arquivos) | 🟢 Existe no app (mensagens, uploads) |
| 2 | Criptografia simétrica autoral | 🟢 **Feito** (`app/crypto/`) |
| 3 | Esteganografia (ocultar em imagem) | 🟢 **Feito** (`app/stego.py`) |
| 4 | Big Data (coleta/processamento de eventos) | 🟡 Parcial (`app/security_log.py`) |
| 5 | Inteligência Artificial (anomalias) | 🔴 Falta |
| 6 | Dashboard de segurança | 🟡 Parcial (`templates/admin/`) |

Legenda: 🟢 pronto · 🟡 parcial · 🔴 não iniciado

---

## 2. O que foi feito

### 2.1. Cifra simétrica autoral — `app/crypto/` ✅ (Parte 2)

Cifra de bloco própria, em **rede de substituição-permutação (SPN)** de 128 bits,
sem bibliotecas de criptografia externas.

| Arquivo | Papel |
|---|---|
| `tables.py` | S-box (confusão) + permutação de bits (difusão), com inversos |
| `key_schedule.py` | Geração **dinâmica** de subchaves (chave mestra + salt por mensagem) |
| `cipher.py` | Bloco SPN + modo CBC + padding PKCS#7 + envelope + helpers |
| `__init__.py` | API pública |
| `__main__.py` | Demonstração via linha de comando |

**Requisitos da Parte 2 atendidos:**

- **Blocos** → 128 bits (16 bytes)
- **XOR** → adição de subchave por rodada (AddRoundKey)
- **Substituição** → S-box bijetiva de 8 bits
- **Permutação** → permutação dos 128 bits do bloco
- **Chave influencia / não é fixa** → 16 rodadas com subchaves derivadas da
  chave; **salt + IV aleatórios por mensagem** (a mesma mensagem cifra
  diferente a cada vez)
- **Difusão** → permutação de bits espalha cada bit pelo bloco + encadeamento CBC
- **Confusão** → S-box não-linear

**Como testar:**
```bash
cd academic-hub
python -m app.crypto demo
python -m app.crypto enc "mensagem" chave
python -m app.crypto dec <base64>  chave
```

### 2.2. Esteganografia + hash de senha — `app/stego.py` ✅ (Parte 5 / objetivos)

- Senha → hash **Argon2id** (salt aleatório por hash).
- Hash escondido nos **bits menos significativos (LSB)** de um PNG gerado por código.
- PNG salvo no banco (`users.ps_images`).
- Coluna `users.password` vira **honeypot** (MD5 de senha falsa) → tentativa de
  login com ela dispara o evento `HONEYPOT_TRIGGERED`.
- Já integrado ao fluxo de login/registro (`app/routes/auth.py`).

### 2.3. Suíte de ataques + avaliação — `scripts/ataques/` ✅ (Partes 3 e 4)

| Arquivo | Ataque / análise |
|---|---|
| `avalanche.py` | Efeito avalanche (texto, chave, por rodada, CBC) |
| `diferencial.py` | Ataque diferencial (distribuição de Δout) |
| `forca_bruta.py` | Espaço de chaves + quebra real de PIN + extrapolação |
| `estatistico.py` | Entropia, qui-quadrado, frequência, padrões ECB |
| `run_all.py` | Roda tudo e gera `resultados/relatorio_ataques.md` |

**Como rodar:**
```bash
cd academic-hub
python -m scripts.ataques.run_all
```

---

## 3. Resultados dos testes (Parte 4)

> Números gerados por `scripts/ataques/run_all.py`.

### Efeito avalanche
| Teste | Mudança média | Ideal |
|---|---|---|
| 1 bit no texto claro | **49,98%** | 50% |
| 1 bit na chave | **50,05%** | 50% |
| Modo CBC (mensagem) | 33,5% | — (ver nota) |

A difusão satura já na **rodada 4–5**. *Nota:* os 33,5% do CBC são esperados —
no CBC a mudança se propaga só "para frente" (um bit no bloco *i* afeta os
blocos *i..n*). A propriedade da **cifra** é a do bloco (≈50%); os 33,5% são
característica do **modo de operação**, não fraqueza.

### Ataque diferencial
- Peso médio de Δout: **63,94 / 128** (ideal ~64)
- Δout distintos: **4000/4000** (nenhuma repetição)
- Probabilidade da característica mais provável: **0,00025** → **inviável**

### Força bruta
- PIN fraco (4 dígitos): quebrado em **43 tentativas** (~0,04s)
- Chave aleatória de 128 bits: **inviável** (≈ 2¹²⁷ tentativas, bilhões de anos)

### Ataque estatístico
- Entropia do cifrado: **7,996 bits/byte** mesmo cifrando 50 mil "A" (ideal 8,0)
- **Zero** blocos repetidos (não vaza como ECB)
- Frequência de bytes do cifrado é plana → **inviável**

### Respostas da Parte 4
- **O sistema apresenta efeito avalanche?** Sim (~50%).
- **Existem padrões na saída?** Não detectados.
- **Qual ataque foi mais eficaz?** Força bruta — **mas só** contra chave fraca.
- **O sistema é seguro?** Contra diferencial e estatístico, sim neste escopo.
  A segurança depende da entropia da chave. Por ser educacional e **sem MAC**,
  não substitui AES em produção.

---

## 4. O que falta

### 🔴 Faltando por completo

- **IA de detecção de anomalias (Parte 1 / camada 5)**
  - O `app/routes/assistant.py` é um assistente de estudos (Gemini), **não**
    detecta anomalias.
  - Faltam os 5 tipos pedidos: nº incomum de tentativas de auth; frequência
    elevada de falhas de descriptografia; alterações inesperadas em arquivos;
    padrões atípicos de acesso; geração incomum de eventos.

- **Relatório final + slides (Parte 5)**
  - Consolidar: descrição do algoritmo, funcionamento, testes, resultados,
    conclusão. (Este arquivo e o `relatorio_ataques.md` são a base.)

### 🟡 Parcial — falta completar

- **Big Data das operações criptográficas (Parte 1 / camada 4)**
  - Já há `security_log.py` (auth, falhas, honeypot no banco + arquivo).
  - Falta: **logar as operações da cifra** (cifragem/decifragem), armazenar
    **eventos de anomalia** e processar/analisar grande volume.

- **Dashboard de segurança (Parte 5 / camada 6)**
  - Já há `templates/admin/dashboard.html` e `security_logs.html`.
  - Falta: visualizar **ataques, anomalias e resultados dos testes**
    (gráficos/indicadores).

- **Integração da cifra ao app**
  - A cifra está pronta, mas ainda **não é usada** em nenhuma rota.
  - Falta: cifrar um dado real (ex.: mensagens/arquivos) para fechar o fluxo
    *Entrada → Criptografia → Esteganografia*.
  - (Opcional) **MAC de integridade** — liga-se à anomalia "falhas de
    descriptografia".

---

## 5. Checklist consolidado

### Parte 1 — Implementação
- [x] Escolher tipo de dado (texto)
- [ ] Big Data: logs das operações criptográficas
- [x] Big Data: tentativas de acesso / falhas de autenticação
- [ ] Big Data: armazenar eventos de detecção de anomalias
- [ ] Big Data: analisar padrões / processar grande volume

### Parte 2 — Cifra
- [x] Criptografia simétrica autoral
- [x] Chave influencia a cifragem e não é fixa (salt dinâmico)
- [x] XOR, substituição, permutação, blocos
- [x] Difusão e confusão

### Parte 3 — Ataques
- [x] Força bruta (espaço de chaves + viabilidade)
- [x] Diferencial (1 bit, comparar saídas, medir impacto)
- [x] Estatístico (padrões + frequência de caracteres)

### Parte 4 — Avaliação
- [x] Efeito avalanche
- [x] Padrões na saída
- [x] Ataque mais eficaz
- [x] Segurança justificada

### Parte 5 — Entregáveis e demais camadas
- [x] Esteganografia
- [ ] IA de detecção de anomalias
- [ ] Dashboard de ataques/anomalias/testes
- [ ] Relatório final + slides

---

## 6. Como executar o ambiente

```bash
# aplicação web
docker compose up --build -d          # http://localhost:31337 | https://localhost

# demonstração da cifra
cd academic-hub && python -m app.crypto demo

# suíte de ataques (gera scripts/ataques/resultados/relatorio_ataques.md)
cd academic-hub && python -m scripts.ataques.run_all
```

---

## 7. Próximos passos sugeridos (ordem)

1. **Big Data das operações cripto** — instrumentar cifra/decifra em
   `security_log` (gera os dados que a IA vai consumir).
2. **IA de detecção de anomalias** — detectar os 5 padrões sobre esses logs.
3. **Dashboard de segurança** — visualizar ataques, anomalias e resultados.
4. **Relatório final + slides** — consolidar tudo.
