import os
import time
import psycopg2
from app.database import DB_CONFIG, init_db, is_seeded
from app.seed import seed_db
from app import create_app

app = create_app()


def wait_for_db(retries=30, delay=2):
    """Aguarda o PostgreSQL estar pronto antes de iniciar a aplicação."""
    print("[*] Aguardando o banco de dados PostgreSQL...")
    for attempt in range(1, retries + 1):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            print("[*] Banco de dados disponível.")
            return
        except Exception as e:
            print(f"[!] Tentativa {attempt}/{retries}: {e}")
            time.sleep(delay)
    raise RuntimeError("Banco de dados não respondeu a tempo.")


if __name__ == '__main__':
    wait_for_db()
    init_db()
    if not is_seeded():
        seed_db()
        print("[*] Banco de dados populado com dados iniciais.")
    else:
        print("[*] Banco de dados já populado, pulando seed.")
    port = int(os.environ.get('PORT', 31337))
    # debug=True expõe o debugger do Werkzeug (RCE). Fica DESLIGADO por padrão;
    # no lab local o docker-compose define FLASK_DEBUG=1 para reativá-lo.
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(host='0.0.0.0', port=port, debug=debug)
