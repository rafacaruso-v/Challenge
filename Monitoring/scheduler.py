# ASPM Platform - Application Security Posture Management (ASPM) platform that centralizes asset discovery, security scanning (SAST, DAST, SCA, IaC, CSPM, Secrets, DLP), and security findings, consolidating everything into a single application/business risk dashboard.
#
# Copyright (C) 2026 Guilherme Monteiro, Rafael Caruso, João Pedro
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

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
