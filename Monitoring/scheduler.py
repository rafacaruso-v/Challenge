import schedule
import time
import threading
from Monitoring.monitor import rescan_automatico

# =====================================
# CONFIGURAÇÃO DO SCHEDULER
# =====================================

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
        rescan_automatico()
        print("[Scheduler] Re-scan concluído.")

    schedule.clear()       
    schedule.every(10).minutes.do(job)

    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    print("[Scheduler] Re-scan automático agendado a cada 10 minutos.")