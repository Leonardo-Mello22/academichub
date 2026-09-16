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

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.grades import grades_bp
    from .routes.courses import courses_bp
    from .routes.profile import profile_bp
    from .routes.announcements import announcements_bp
    from .routes.messages import messages_bp
    from .routes.files import files_bp
    from .routes.admin import admin_bp
    from .routes.assistant import assistant_bp

    app.register_blueprint(
        auth_bp
    )

    app.register_blueprint(
        dashboard_bp
    )

    app.register_blueprint(
        grades_bp,
        url_prefix='/notas'
    )

    app.register_blueprint(
        courses_bp,
        url_prefix='/disciplinas'
    )

    app.register_blueprint(
        profile_bp,
        url_prefix='/perfil'
    )

    app.register_blueprint(
        announcements_bp,
        url_prefix='/avisos'
    )

    app.register_blueprint(
        messages_bp,
        url_prefix='/mensagens'
    )

    app.register_blueprint(
        files_bp,
        url_prefix='/arquivos'
    )

    app.register_blueprint(
        admin_bp,
        url_prefix='/admin'
    )

    app.register_blueprint(
        assistant_bp
    )

    return app
