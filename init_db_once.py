
# init_db_once.py
from sqlalchemy import inspect
from app import app, db

# se hai una ensure_seed_data nel tuo app.py, la importiamo (se non c'è, ignoriamo)
try:
    from app import ensure_seed_data
except Exception:
    ensure_seed_data = None

with app.app_context():
    insp = inspect(db.engine)
    # usiamo 'users' come tabella sentinella: se non c'è, il DB è vuoto
    if not insp.has_table("users"):
        print("DB vuoto: creo tabelle…")
        db.create_all()
        if ensure_seed_data:
            try:
                ensure_seed_data()
                print("Seed eseguito.")
            except Exception as e:
                print("Tabelle create, seed saltato:", e)
        else:
            print("Tabelle create. Nessuna funzione di seed trovata.")
    else:
        print("Tabelle già presenti: skip init.")