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
http://localhost:31337
```

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
