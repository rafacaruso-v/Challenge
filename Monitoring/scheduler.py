import schedule
import time
import threading
from Monitoring.monitor import rescan_automatico
from Database.db import registrar_historico


_scheduler_iniciado = False
_lock = threading.Lock()

def iniciar_scheduler():
    """
    Roda o scheduler em background sem bloquear o Streamlit.
    Garante que apenas UMA thread/job seja registrada, mesmo que o
    Streamlit re-execute o script várias vezes.
    """
    global _scheduler_iniciado

    with _lock:
        if _scheduler_iniciado:
            return
        _scheduler_iniciado = True

    def job():
        print("[Scheduler] Iniciando re-scan automático...")
        # Sem usuario_id: rescan_automatico() itera por TODOS os usuários
        # cadastrados, já que o scheduler roda em background sem contexto
        # de sessão Streamlit (não há "usuário logado" nesse momento).
        rescan_automatico()
        print("[Scheduler] Re-scan concluído para todos os usuários.")

    schedule.clear()
    schedule.every(60).minutes.do(job)

    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    print("[Scheduler] Re-scan automático agendado a cada 1 hora.")