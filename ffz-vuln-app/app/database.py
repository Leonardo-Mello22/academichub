import os
import psycopg2
import psycopg2.extras

DB_CONFIG = {
    'host': os.environ.get('PG_HOST', 'localhost'),
    'port': int(os.environ.get('PG_PORT', 5432)),
    'user': os.environ.get('PG_USER', 'academichub'),
    'password': os.environ.get('PG_PASSWORD', 'academichub123'),
    'dbname': os.environ.get('PG_DATABASE', 'academichub'),
}


def get_db():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn


def query_db(query, args=(), one=False):
    """Helper seguro com queries parametrizadas."""
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(query, args)
            rv = cur.fetchall()

        return (rv[0] if rv else None) if one else rv

    finally:
        conn.close()


def execute_db(query, args=()):
    """Helper seguro para INSERT/UPDATE/DELETE parametrizados."""
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(query, args)

            try:
                return cur.fetchone()[0]
            except Exception:
                return None

    finally:
        conn.close()


def unsafe_query(query):
    """
    INTENCIONALMENTE INSEGURO — utilizado pelas rotas vulneráveis.

    Executa strings SQL diretamente sem parametrização.

    NÃO UTILIZE EM CÓDIGO DE PRODUÇÃO.
    """
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(query)

            try:
                return cur.fetchall()
            except Exception:
                return []

    except Exception:
        return []

    finally:
        conn.close()


def init_db():
    """Cria o schema do banco de dados no PostgreSQL."""
    conn = get_db()

    try:
        with conn.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    email VARCHAR(128) UNIQUE NOT NULL,
                    password VARCHAR(64) NOT NULL,
                    role VARCHAR(20) DEFAULT 'aluno',
                    full_name VARCHAR(128),
                    student_id VARCHAR(20),
                    gpa FLOAT DEFAULT 0.0,
                    bio TEXT,
                    is_active SMALLINT DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS courses (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR(20) UNIQUE NOT NULL,
                    name VARCHAR(128) NOT NULL,
                    description TEXT,
                    professor_id INT REFERENCES users(id),
                    max_students INT DEFAULT 40
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS enrollments (
                    id SERIAL PRIMARY KEY,
                    student_id INT REFERENCES users(id),
                    course_id INT REFERENCES courses(id),
                    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS grades (
                    id SERIAL PRIMARY KEY,
                    student_id INT REFERENCES users(id),
                    course_id INT REFERENCES courses(id),
                    assignment_name VARCHAR(128),
                    grade FLOAT,
                    feedback TEXT,
                    submitted_by INT REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS announcements (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(256),
                    body TEXT,
                    author_id INT REFERENCES users(id),
                    course_id INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender_id INT REFERENCES users(id),
                    recipient_id INT REFERENCES users(id),
                    subject VARCHAR(256),
                    body TEXT,
                    is_read SMALLINT DEFAULT 0,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS uploads (
                    id SERIAL PRIMARY KEY,
                    uploader_id INT REFERENCES users(id),
                    course_id INT,
                    filename VARCHAR(256),
                    original_name VARCHAR(256),
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id),
                    token INT,
                    used SMALLINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    finally:
        conn.close()


def is_seeded():
    """Verifica se o banco já foi populado com os dados iniciais."""
    try:
        row = query_db(
            "SELECT COUNT(*) FROM users",
            one=True
        )

        return row and row[0] > 0

    except Exception:
        return False
