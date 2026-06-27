import schedule
import time
import threading
from Monitoring.monitor import rescan_automatico
from Database.db import registrar_historico


_scheduler_iniciado = False
_lock = threading.Lock()

def iniciar_scheduler():
    global _scheduler_iniciado

    with _lock:
        if _scheduler_iniciado:
            return
        _scheduler_iniciado = True

    def job():
        print("[Scheduler] Iniciando re-scan automático...")
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