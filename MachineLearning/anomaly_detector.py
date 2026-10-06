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

import numpy as np
from Database.db import listar_historico_componente

MINIMO_PONTOS_PARA_ML = 5
LIMIAR_ANOMALIA_SIMPLES = 20
LIMIAR_DECISION_FUNCTION = -0.15
LIMIAR_Z_SCORE = 1.5


def _detectar_anomalia_regra_simples(scores_historicos: list, score_atual: int):
    if not scores_historicos:
        return False, None

    score_anterior = scores_historicos[-1]
    diferenca = score_atual - score_anterior

    if diferenca >= LIMIAR_ANOMALIA_SIMPLES:
        return True, f"aumento brusco de score: {score_anterior} → {score_atual} (+{diferenca} pontos)"

    return False, None


def _detectar_anomalia_ml(scores_historicos: list, score_atual: int):
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return _detectar_anomalia_regra_simples(scores_historicos, score_atual)

    dados = np.array(scores_historicos + [score_atual]).reshape(-1, 1)

    modelo = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42
    )
    modelo.fit(dados)

    intensidade = modelo.decision_function(dados)[-1]

    media_historica = float(np.mean(scores_historicos))
    desvio_padrao = float(np.std(scores_historicos)) or 1.0
    z_score = abs(score_atual - media_historica) / desvio_padrao

    e_anomalia = (intensidade < LIMIAR_DECISION_FUNCTION) and (z_score >= LIMIAR_Z_SCORE)

    if e_anomalia:
        direcao = "acima" if score_atual > media_historica else "abaixo"
        mensagem = (
            f"padrão fora do esperado detectado por ML: score atual {score_atual} está "
            f"{direcao} da média histórica ({media_historica:.1f}, desvio {desvio_padrao:.1f}). "
            f"Intensidade da anomalia: {intensidade:.3f}"
        )
        return True, mensagem

    return False, None


def verificar_anomalia_ml(usuario_id: int, componente_id: int, identificador_exibicao: str, score_atual: int):
 
    historico = listar_historico_componente(usuario_id, componente_id, limite=50)
    scores_historicos = [h[0] for h in historico if h[0] is not None]

    if len(scores_historicos) < MINIMO_PONTOS_PARA_ML:
        e_anomalia, detalhe = _detectar_anomalia_regra_simples(scores_historicos, score_atual)
        metodo = "regra_simples"
    else:
        e_anomalia, detalhe = _detectar_anomalia_ml(scores_historicos, score_atual)
        metodo = "machine_learning"

    return e_anomalia, detalhe, metodo
