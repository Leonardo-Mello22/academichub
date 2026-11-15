# AcademicHub

## Descrição

O **AcademicHub** é uma aplicação web acadêmica fictícia desenvolvida para fins educacionais.

A plataforma simula um portal universitário com diferentes perfis de usuário, como **aluno**, **professor** e **administrador**, permitindo o acesso a funcionalidades como disciplinas, notas, avisos, mensagens, arquivos e informações de perfil.

O projeto também funciona como ambiente controlado para análise de segurança, exploração de vulnerabilidades, aplicação de correções e retestes. Algumas vulnerabilidades são mantidas intencionalmente durante determinadas etapas do projeto para permitir a demonstração prática desse ciclo.

## Organização do projeto

O sistema é dividido nas camadas do trabalho de Cibersegurança. Cada camada
fica em um lugar próprio:

```text
academic-hub/
├── app/                      código da aplicação
│   ├── __init__.py           fábrica Flask + registro das rotas
│   ├── database.py           schema e helpers do PostgreSQL
│   ├── seed.py               dados iniciais
│   ├── routes/               1. entrada de dados: páginas (login, notas, arquivos, admin...)
│   ├── crypto/               2. criptografia: AcademicCipher (cifra autoral SPN)
│   ├── stego.py              3. esteganografia: hash Argon2id escondido em PNG
│   └── bigdata/              4. Big Data: eventos, logs cripto, anomalias, análise
│       ├── events.py            coleta  -> banco + logs/security_events.jsonl
│       ├── crypto_ops.py        cifra/decifra com log
│       ├── anomalies.py         armazenamento das anomalias detectadas
│       ├── analysis.py          análise de padrões em grande volume
│       └── simulation.py        gerador de eventos sintéticos
├── scripts/ataques/          ataques à cifra (avalanche, diferencial, força bruta, estatístico)
├── templates/  static/       interface web
├── docs/relatorio.md         progresso do trabalho (o que foi feito / o que falta)
├── logs/                     eventos JSONL (gerado em execução, fora do git)
└── nginx/                    proxy HTTPS
```

### Comandos úteis

```bash
# demonstração da cifra
docker compose exec academichub python -m app.crypto demo

# Big Data: operações cripto reais, análise do banco e teste de volume
docker compose exec academichub python -m app.bigdata cripto --operacoes 50
docker compose exec academichub python -m app.bigdata analisar --banco --registrar
docker compose exec academichub python -m app.bigdata simular --eventos 1000000
docker compose exec academichub python -m app.bigdata analisar logs/simulado.jsonl

# suíte de ataques (gera scripts/ataques/resultados/relatorio_ataques.md)
python -m scripts.ataques.run_all
```

Painel de segurança (admin): `/admin/logs` e `/admin/analise`.

## Como executar

### Pré-requisitos

- Docker
- Docker Compose

### Iniciar a aplicação

No diretório do projeto, execute:

```bash
docker compose up --build -d
```

A aplicação ficará disponível em:

```text
http://localhost:31337   (Flask direto, sem TLS)
https://localhost        (via proxy Nginx, com HTTPS)
```

### HTTPS

A comunicação HTTPS é feita por um proxy reverso Nginx (`nginx/`) que termina TLS
usando um **certificado autoassinado**, gerado automaticamente no build da imagem
(`nginx/Dockerfile`). Por se tratar de um ambiente de laboratório/controlado, o
navegador exibirá um aviso de certificado não confiável — isso é esperado. Em um
ambiente de produção real, esse certificado seria substituído por um emitido por
uma CA confiável (ex: Let's Encrypt).

O acesso direto à porta `31337` (HTTP puro, sem TLS) foi mantido de propósito para
permitir comparar o tráfego "antes" (sem criptografia) e "depois" (via HTTPS na
porta 443) como evidência na etapa de análise de segurança.

Para acompanhar os logs:

```bash
docker compose logs -f
```

### Parar a aplicação

```bash
docker compose down
```

### Reiniciar o ambiente com o banco de dados limpo

```bash
docker compose down -v
docker compose up --build -d
```

> O uso de `-v` remove os volumes do Docker e apaga os dados persistidos no banco.
