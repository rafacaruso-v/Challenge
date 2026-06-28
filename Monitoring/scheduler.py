import schedule
import time
import threading
from Database.db import registrar_historico, get_intervalo_rescan

_scheduler_iniciado = False
_lock = threading.Lock()
_thread = None


def _criar_job():
    from Monitoring.monitor import rescan_automatico
    def job():
        print("[Scheduler] Iniciando re-scan automático...")
        rescan_automatico()
        print("[Scheduler] Re-scan concluído para todos os usuários.")
    return job


def iniciar_scheduler():
    global _scheduler_iniciado, _thread

    with _lock:
        if _scheduler_iniciado:
            return
        _scheduler_iniciado = True

    intervalo = get_intervalo_rescan()
    schedule.clear()
    schedule.every(intervalo).minutes.do(_criar_job())

    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)

    _thread = threading.Thread(target=loop, daemon=True)
    _thread.start()
    print(f"[Scheduler] Re-scan automático agendado a cada {intervalo} minutos.")


def reiniciar_scheduler(novo_intervalo: int):
    global _scheduler_iniciado

    with _lock:
        schedule.clear()
        schedule.every(novo_intervalo).minutes.do(_criar_job())
        _scheduler_iniciado = True

    print(f"[Scheduler] Re-scan reagendado para a cada {novo_intervalo} minutos.")