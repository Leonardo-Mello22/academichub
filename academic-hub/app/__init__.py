"""
AcademicHub — fábrica da aplicação Flask.

Organização do pacote `app/` (camadas do projeto):

    routes/     páginas web (blueprints)            camada 1 — entrada de dados
    crypto/     AcademicCipher (cifra autoral)      camada 2 — criptografia
    stego.py    hash Argon2id escondido em PNG      camada 3 — esteganografia
    bigdata/    eventos, logs cripto, anomalias     camada 4 — Big Data
    database.py schema e helpers do PostgreSQL
    seed.py     dados iniciais
"""

from flask import Flask


def create_app():
    app = Flask(
        __name__,
        template_folder='../templates',
        static_folder='../static'
    )

    app.config['SECRET_KEY'] = 'secret'
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_SAMESITE'] = None
    app.config['DEBUG'] = True

    _register_blueprints(app)

    return app


def _register_blueprints(app):
    from .routes.admin import admin_bp
    from .routes.announcements import announcements_bp
    from .routes.assistant import assistant_bp
    from .routes.auth import auth_bp
    from .routes.courses import courses_bp
    from .routes.dashboard import dashboard_bp
    from .routes.files import files_bp
    from .routes.grades import grades_bp
    from .routes.messages import messages_bp
    from .routes.profile import profile_bp

    # (blueprint, prefixo da URL)
    blueprints = (
        (auth_bp, None),
        (dashboard_bp, None),
        (assistant_bp, None),
        (grades_bp, '/notas'),
        (courses_bp, '/disciplinas'),
        (profile_bp, '/perfil'),
        (announcements_bp, '/avisos'),
        (messages_bp, '/mensagens'),
        (files_bp, '/arquivos'),
        (admin_bp, '/admin'),
    )

    for blueprint, prefix in blueprints:
        app.register_blueprint(blueprint, url_prefix=prefix)
