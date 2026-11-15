# Relatório de Progresso — Projeto Cibersegurança (AcademicCipher)

**Projeto:** Sistema Criptográfico + Análise de Ataques
**Base:** AcademicHub (portal acadêmico fictício em Flask + PostgreSQL)
**Atualizado em:** 2026-11-15

Este documento registra **o que já foi feito** e **o que ainda falta**, mapeado
às partes do enunciado da disciplina (Partes 1 a 5).

---

## 1. Visão geral da arquitetura (6 camadas)

| # | Camada | Status |
|---|---|---|
| 1 | Entrada de dados (texto/arquivos) | 🟢 Existe no app (mensagens, uploads) |
| 2 | Criptografia simétrica autoral | 🟢 **Feito** (`app/crypto/`) |
| 3 | Esteganografia (ocultar em imagem) | 🟢 **Feito** (`app/stego.py`) |
| 4 | Big Data (coleta/processamento de eventos) | 🟢 **Feito** (`app/bigdata/`) |
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

### 2.3. Big Data — `app/bigdata/` ✅ (Parte 1 / camada 4)

Coleta, armazenamento e análise dos eventos de segurança.

| Arquivo | Papel |
|---|---|
| `events.py` | `log_security_event()` → tabela `security_logs` **e** `logs/security_events.jsonl` (1 evento JSON por linha) |
| `crypto_ops.py` | Cifra/decifra **auditadas**: eventos `CRYPTO_ENCRYPT`, `CRYPTO_DECRYPT`, `CRYPTO_DECRYPT_FAILURE` (tamanho, blocos, duração, id do envelope — nunca chave nem texto claro) |
| `anomalies.py` | `record_anomaly()` → tabela `anomaly_events` (tipo, score, alvo, evidências, status) + evento `ANOMALY_DETECTED` |
| `analysis.py` | Processamento **em fluxo** (1 passada, memória constante) do JSONL ou do banco (cursor de servidor em lotes) + regras de padrões suspeitos |
| `simulation.py` | Gera milhões de eventos sintéticos com ataques injetados |
| `__main__.py` | CLI `python -m app.bigdata {simular,analisar,cripto}` |

**Requisitos da Parte 1 atendidos:**

- **Logs das operações criptográficas** → `crypto_ops.py` (o pacote `app/crypto`
  continua puro, para a suíte de ataques não gerar milhões de eventos).
- **Tentativas de acesso / falhas de autenticação** → `LOGIN_SUCCESS`,
  `LOGIN_FAILURE` (motivo), `REGISTER*`, `LOGOUT`, `PASSWORD_RESET*`,
  `HONEYPOT_TRIGGERED`, `ADMIN_ACCESS_DENIED`. *(Os logs de login/registro/reset
  tinham sido removidos sem querer no commit `7eada43` e foram restaurados.)*
- **Armazenar eventos de detecção de anomalias** → tabela `anomaly_events`
  com os 5 tipos do enunciado (`AUTH_ATTEMPTS`, `DECRYPT_FAILURES`,
  `FILE_CHANGES`, `ACCESS_PATTERN`, `EVENT_VOLUME`) e status de tratamento.
- **Analisar padrões / processar grande volume** → agregação em fluxo +
  regras com mínimo absoluto **e** detecção de outliers (z-score robusto,
  mediana/MAD), que se adaptam ao volume.

**Resultado do teste de volume** (dentro do container):

| Cenário | Eventos | Tempo | Padrões encontrados |
|---|---|---|---|
| Tráfego normal | 200 mil | ~1,3 s | **0** (sem falsos positivos) |
| Normal + ataques injetados | 1,24 milhão (318 MB) | ~8,1 s (**~150 mil eventos/s**) | 29 — os **5 tipos** de anomalia, incluindo os 20 IPs da botnet |

**Como testar:**
```bash
docker compose exec academichub python -m app.bigdata cripto --operacoes 50
docker compose exec academichub python -m app.bigdata analisar --banco --registrar
docker compose exec academichub python -m app.bigdata simular --eventos 1000000
docker compose exec academichub python -m app.bigdata analisar logs/simulado.jsonl
```
Painel: **Admin → Análise de Eventos e Anomalias** (`/admin/analise`).

### 2.4. Suíte de ataques + avaliação — `scripts/ataques/` ✅ (Partes 3 e 4)

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

- **IA de detecção de anomalias (Parte 5 / camada 5)**
  - O `app/routes/assistant.py` é um assistente de estudos (Gemini), **não**
    detecta anomalias.
  - Já existe a base: as regras estatísticas de `app/bigdata/analysis.py`
    detectam os 5 tipos, e `record_anomaly(..., detector='ia')` é o ponto de
    gravação. Falta o modelo de IA em si (ex.: Isolation Forest sobre as
    features por IP/usuário/hora produzidas pelo `EventAggregator`).

- **Relatório final + slides (Parte 5)**
  - Consolidar: descrição do algoritmo, funcionamento, testes, resultados,
    conclusão. (Este arquivo e o `relatorio_ataques.md` são a base.)

### 🟡 Parcial — falta completar

- **Dashboard de segurança (Parte 5 / camada 6)**
  - Já há `templates/admin/dashboard.html`, `security_logs.html` e
    `analysis.html` (`/admin/analise`: volume, padrões e anomalias em tabelas).
  - Falta: visualizar **ataques, anomalias e resultados dos testes**
    (gráficos/indicadores).

- **Integração da cifra ao app**
  - A cifra está pronta, mas ainda **não é usada** em nenhuma rota.
  - Falta: cifrar um dado real (ex.: mensagens/arquivos) para fechar o fluxo
    *Entrada → Criptografia → Esteganografia*. Usar
    `app.bigdata.crypto_ops.encrypt_text/decrypt_text` para que as operações
    já entrem nos logs (hoje elas vêm do comando `python -m app.bigdata cripto`).
  - (Opcional) **MAC de integridade** — liga-se à anomalia "falhas de
    descriptografia".

---

## 5. Checklist consolidado

### Parte 1 — Implementação
- [x] Escolher tipo de dado (texto)
- [x] Big Data: logs das operações criptográficas
- [x] Big Data: tentativas de acesso / falhas de autenticação
- [x] Big Data: armazenar eventos de detecção de anomalias
- [x] Big Data: analisar padrões / processar grande volume

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

1. **Integrar a cifra ao app** — cifrar mensagens/arquivos via
   `app.bigdata.crypto_ops` (gera logs cripto reais).
2. **IA de detecção de anomalias** — modelo sobre os eventos de `app/bigdata`,
   gravando com `record_anomaly(detector='ia')`.
3. **Dashboard de segurança** — evoluir `/admin/analise` com gráficos e os
   resultados da suíte de ataques.
4. **Relatório final + slides** — consolidar tudo.
