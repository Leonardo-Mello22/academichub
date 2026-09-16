# AcademicHub

## Descrição

O **AcademicHub** é uma aplicação web acadêmica fictícia desenvolvida para fins educacionais.

A plataforma simula um portal universitário com diferentes perfis de usuário, como **aluno**, **professor** e **administrador**, permitindo o acesso a funcionalidades como disciplinas, notas, avisos, mensagens, arquivos e informações de perfil.

O projeto também funciona como ambiente controlado para análise de segurança, exploração de vulnerabilidades, aplicação de correções e retestes. Algumas vulnerabilidades são mantidas intencionalmente durante determinadas etapas do projeto para permitir a demonstração prática desse ciclo.

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
