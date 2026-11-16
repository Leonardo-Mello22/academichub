# AcademicHub

## Descrição

O **AcademicHub** é uma aplicação web acadêmica fictícia desenvolvida para fins educacionais.

A plataforma simula um portal universitário com diferentes perfis de usuário, como **aluno**, **professor** e **administrador**, permitindo o acesso a funcionalidades como disciplinas, notas, avisos, mensagens, arquivos e informações de perfil.

O projeto também funciona como ambiente controlado para análise de segurança, exploração de vulnerabilidades, aplicação de correções e retestes. Algumas vulnerabilidades são mantidas intencionalmente durante determinadas etapas do projeto para permitir a demonstração prática desse ciclo.

Além do portal, o repositório inclui:

- **AcademicCipher** — cifra simétrica autoral (`app/crypto/`)
- **Big Data + IA** — coleta de eventos, análise de padrões e Isolation Forest (`app/bigdata/`)
- **Dashboard de segurança** — gráficos, anomalias e resultados dos testes (`/admin/analise`)
- **Suíte de ataques** à cifra (`scripts/ataques/`)

---

## Como executar (obrigatório primeiro)

### Pré-requisitos

- Docker
- Docker Compose

### Subir a aplicação

No diretório `academic-hub/`:

```bash
docker compose up --build -d
```

Aguarde os containers ficarem healthy. A aplicação fica em:

```text
http://localhost:31337   (Flask direto, sem TLS)
https://localhost        (via proxy Nginx, com HTTPS)
```

> No HTTPS o navegador avisa certificado autoassinado — é esperado em laboratório.

### Contas de teste (seed)

| Usuário   | Senha      | Papel   |
|-----------|------------|---------|
| `admin`   | `admin123` | admin   |
| (outros)  | ver seed   | aluno / professor |

O painel de **logs** e o **dashboard de segurança** exigem login como **`admin`**.

### Parar / resetar

```bash
docker compose down          # para
docker compose down -v       # para e APAGA o banco (dados limpos)
docker compose up --build -d
```

---

## Ver dados nos logs e no dashboard (guia para o time)

Os gráficos de `/admin/analise` leem o **PostgreSQL** (`security_logs` / `anomaly_events`).  
Só gerar JSONL com `simular` **não** preenche o dashboard — use `--banco` ou `importar`.

### Passo a passo recomendado

```bash
# 1) Subir a stack (se ainda não estiver)
docker compose up --build -d

# 2) Popular o banco com eventos sintéticos (auth, cripto, arquivos, ataques)
#    --substituir remove simulados antigos antes de inserir
docker compose exec academichub python -m app.bigdata simular \
  --eventos 30000 --banco --substituir

# 3) (Opcional) variar o padrão dos dados
docker compose exec academichub python -m app.bigdata simular \
  --eventos 30000 --seed 99 --banco --substituir

# 4) Treinar IA + detectar + gravar anomalias + importar tráfego com ataques
docker compose exec academichub python -m app.bigdata ia pipeline \
  --eventos 30000 --banco --substituir --registrar

# 5) (Opcional) operações reais da cifra → eventos CRYPTO_* no banco
docker compose exec academichub python -m app.bigdata cripto --operacoes 100

# 6) (Opcional) regenerar o relatório dos testes à cifra (avalanche etc.)
docker compose exec academichub python -m scripts.ataques.run_all
```

### Onde ver no navegador

1. Abra `http://localhost:31337`
2. Entre com **`admin` / `admin123`**
3. Menu **Admin**:
   - **`/admin/logs`** — lista de eventos de segurança (login, cripto, honeypot, etc.)
   - **`/admin/analise`** — **Dashboard de Segurança**:
     - cards de volume / falhas / cripto / anomalias
     - gráficos (Chart.js): por hora, categoria, IPs, cripto, alertas
     - resultados dos testes da AcademicCipher (avalanche, diferencial, …)
     - tabelas de padrões (regras + IA) e anomalias registradas
4. Na análise, escolha a janela **Últimos 7 dias** (os eventos simulados cobrem ~72h)

### Só importar um JSONL que já existe

```bash
docker compose exec academichub python -m app.bigdata importar logs/ataques.jsonl --substituir
# ou
docker compose exec academichub python -m app.bigdata importar logs/simulado.jsonl --substituir
```

### Gerar eventos “de verdade” pelo uso do portal

Além da simulação, o app também grava logs quando você:

- faz login (sucesso / falha / honeypot)
- envia **mensagens** (corpo cifrado → `CRYPTO_*`)
- faz **upload/download** de arquivos (conteúdo cifrado → `CRYPTO_*` + `FILE_*`)

Isso aparece em `/admin/logs` e entra na janela do dashboard.

---

## Organização do projeto

```text
academic-hub/
├── app/
│   ├── routes/               páginas (login, notas, arquivos, admin…)
│   ├── crypto/               AcademicCipher (cifra SPN)
│   ├── stego.py              Argon2id + esteganografia LSB
│   └── bigdata/              Big Data + IA
│       ├── events.py         log → banco + JSONL (+ importar)
│       ├── crypto_ops.py     cifra/decifra auditada
│       ├── analysis.py       regras de padrões
│       ├── ia.py             Isolation Forest
│       ├── simulation.py     gerador sintético
│       └── attack_report.py  lê relatorio_ataques.md p/ o dashboard
├── scripts/ataques/          suíte de ataques à cifra
├── templates/admin/          logs + dashboard Chart.js
├── docs/relatorio.md         progresso do trabalho
├── logs/                     JSONL / modelos IA (gerados em runtime)
└── nginx/                    proxy HTTPS
```

---

## Referência rápida de comandos

Todos os comandos abaixo partem de `academic-hub/` com a stack no ar
(`docker compose up -d`).

| Objetivo | Comando |
|---|---|
| Demo da cifra | `docker compose exec academichub python -m app.crypto demo` |
| Simular + **encher o dashboard** | `... python -m app.bigdata simular --eventos 30000 --banco --substituir` |
| Importar JSONL → banco | `... python -m app.bigdata importar logs/simulado.jsonl --substituir` |
| Analisar só o arquivo | `... python -m app.bigdata analisar logs/simulado.jsonl` |
| Analisar o banco + registrar regras | `... python -m app.bigdata analisar --banco --registrar` |
| Pipeline IA (+ banco + anomalias) | `... python -m app.bigdata ia pipeline --eventos 30000 --banco --registrar` |
| CRYPTO_* reais | `... python -m app.bigdata cripto --operacoes 100` |
| Relatório dos ataques à cifra | `... python -m scripts.ataques.run_all` |
| Logs do container | `docker compose logs -f academichub` |

Flags úteis do `simular`:

- `--banco` — grava também em `security_logs` (necessário para o dashboard)
- `--substituir` — apaga eventos com `(simulado)` antes de importar
- `--seed N` — muda o padrão dos dados sintéticos
- `--sem-ataques` — só tráfego “normal” (bom para treinar a IA)

---

## HTTPS (contexto de laboratório)

A comunicação HTTPS é feita por um proxy reverso Nginx (`nginx/`) com
**certificado autoassinado**. O aviso do navegador é esperado.

A porta `31337` (HTTP) foi mantida de propósito para comparar tráfego
com e sem TLS.

---

## Documentação extra

- Progresso e checklist do trabalho: [`docs/relatorio.md`](docs/relatorio.md)
- Números da suíte de ataques: `scripts/ataques/resultados/relatorio_ataques.md`
