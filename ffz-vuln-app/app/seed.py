import hashlib

from app.database import get_db


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def seed_db():
    conn = get_db()

    try:
        with conn.cursor() as cur:

            # ---------- Usuários ----------

            users = [
                (
                    1,
                    'admin',
                    'admin@academichub.edu.br',
                    md5('admin123'),
                    'admin',
                    'Administrador do Sistema',
                    None,
                    4.0,
                    'Administrador da plataforma AcademicHub.'
                ),
                (
                    2,
                    'prof.silva',
                    'silva@academichub.edu.br',
                    md5('professor1'),
                    'professor',
                    'Prof. Dr. Ricardo Silva',
                    None,
                    4.0,
                    'Docente de Segurança da Informação e Redes.'
                ),
                (
                    3,
                    'prof.mendes',
                    'mendes@academichub.edu.br',
                    md5('iloveteaching'),
                    'professor',
                    'Profa. Ana Mendes',
                    None,
                    4.0,
                    'Docente de Desenvolvimento Web e Banco de Dados.'
                ),
                (
                    4,
                    'alice',
                    'alice@aluno.academichub.edu.br',
                    md5('password123'),
                    'aluno',
                    'Alice Ferreira',
                    'A2024001',
                    3.7,
                    'Estudante de Análise e Desenvolvimento de Sistemas.'
                ),
                (
                    5,
                    'bob',
                    'bob@aluno.academichub.edu.br',
                    md5('qwerty'),
                    'aluno',
                    'Bob Nascimento',
                    'A2024002',
                    2.9,
                    'Estudante de Redes de Computadores.'
                ),
                (
                    6,
                    'charlie',
                    'charlie@aluno.academichub.edu.br',
                    md5('charlie99'),
                    'aluno',
                    'Charlie Rocha',
                    'A2024003',
                    2.1,
                    'Estudante de Ciência da Computação.'
                ),
            ]

            for user in users:
                cur.execute(
                    """
                    INSERT INTO users (
                        id,
                        username,
                        email,
                        password,
                        role,
                        full_name,
                        student_id,
                        gpa,
                        bio
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    user
                )

            cur.execute(
                "SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))"
            )

            # ---------- Disciplinas ----------

            courses = [
                (
                    1,
                    'SI101',
                    'Introdução à Segurança da Informação',
                    'Fundamentos de segurança, criptografia e políticas de acesso.',
                    2,
                    40
                ),
                (
                    2,
                    'DS301',
                    'Desenvolvimento Web Seguro',
                    'Boas práticas de desenvolvimento e prevenção de vulnerabilidades.',
                    3,
                    40
                ),
                (
                    3,
                    'RC201',
                    'Redes de Computadores II',
                    'Protocolos de rede, VPNs e análise de tráfego.',
                    2,
                    35
                ),
            ]

            for course in courses:
                cur.execute(
                    """
                    INSERT INTO courses (
                        id,
                        code,
                        name,
                        description,
                        professor_id,
                        max_students
                    )
                    VALUES (%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    course
                )

            cur.execute(
                "SELECT setval('courses_id_seq', (SELECT MAX(id) FROM courses))"
            )

            # ---------- Matrículas ----------

            enrollments = [
                (4, 1),
                (4, 2),
                (4, 3),
                (5, 1),
                (5, 3),
                (6, 2),
            ]

            for enrollment in enrollments:
                cur.execute(
                    """
                    INSERT INTO enrollments (
                        student_id,
                        course_id
                    )
                    VALUES (%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    enrollment
                )

            # ---------- Notas ----------

            grades = [
                (
                    4,
                    1,
                    'Prova 1',
                    9.5,
                    'Excelente desempenho.',
                    2
                ),
                (
                    4,
                    2,
                    'Trabalho Final',
                    8.8,
                    'Ótima entrega.',
                    3
                ),
                (
                    4,
                    3,
                    'Prova 1',
                    7.2,
                    'Revisem protocolos de roteamento.',
                    2
                ),
                (
                    5,
                    1,
                    'Prova 1',
                    8.3,
                    'Bom trabalho.',
                    2
                ),
                (
                    5,
                    3,
                    'Prova 1',
                    9.1,
                    'Parabéns.',
                    2
                ),
                (
                    6,
                    2,
                    'Trabalho Final',
                    6.2,
                    'Pode melhorar a documentação.',
                    3
                ),
            ]

            for grade in grades:
                cur.execute(
                    """
                    INSERT INTO grades (
                        student_id,
                        course_id,
                        assignment_name,
                        grade,
                        feedback,
                        submitted_by
                    )
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    grade
                )

            # ---------- Avisos ----------

            cur.execute(
                """
                INSERT INTO announcements (
                    id,
                    title,
                    body,
                    author_id,
                    course_id
                )
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    1,
                    'Bem-vindos ao semestre 2024/2!',
                    'Prezados alunos e professores, o semestre letivo '
                    '2024/2 está oficialmente iniciado. '
                    'Consultem o calendário acadêmico para datas de provas '
                    'e entrega de trabalhos. '
                    'Qualquer dúvida, entre em contato com a coordenação.',
                    1,
                    None
                )
            )

            # Aviso com XSS pré-semeado (V-02)

            cur.execute(
                """
                INSERT INTO announcements (
                    id,
                    title,
                    body,
                    author_id,
                    course_id
                )
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    2,
                    'Atualização do Material de SI101',
                    'Alunos de SI101, o material complementar da semana 3 '
                    'foi atualizado no portal. '
                    'Acesse a área de arquivos para baixar o PDF revisado.<br>'
                    '<b>Atenção:</b> confiram também o fórum de discussões '
                    'para novidades sobre a prova. '
                    '<img src=x onerror="console.log(\'[AcademicHub] Cookie: '
                    '\'+document.cookie)">',
                    2,
                    1
                )
            )

            cur.execute(
                "SELECT setval("
                "'announcements_id_seq', "
                "(SELECT MAX(id) FROM announcements)"
                ")"
            )

            # ---------- Mensagem de boas-vindas ----------

            cur.execute(
                """
                INSERT INTO messages (
                    id,
                    sender_id,
                    recipient_id,
                    subject,
                    body
                )
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    1,
                    1,
                    4,
                    'Bem-vinda ao AcademicHub!',
                    'Olá Alice, seja bem-vinda ao portal acadêmico. '
                    'Caso tenha dúvidas sobre o uso do sistema, '
                    'entre em contato com a administração.'
                )
            )

            cur.execute(
                "SELECT setval("
                "'messages_id_seq', "
                "(SELECT MAX(id) FROM messages)"
                ")"
            )

            # ---------- Tokens de reset (sequenciais — V-14) ----------

            cur.execute(
                """
                INSERT INTO password_reset_tokens (
                    id,
                    user_id,
                    token,
                    used
                )
                VALUES (%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    1,
                    1,
                    1001,
                    1
                )
            )

            cur.execute(
                """
                INSERT INTO password_reset_tokens (
                    id,
                    user_id,
                    token,
                    used
                )
                VALUES (%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    2,
                    2,
                    1002,
                    0
                )
            )

            cur.execute(
                "SELECT setval("
                "'password_reset_tokens_id_seq', "
                "(SELECT MAX(id) FROM password_reset_tokens)"
                ")"
            )

    finally:
        conn.close()
