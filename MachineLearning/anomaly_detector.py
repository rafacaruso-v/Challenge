import numpy as np
from Database.db import listar_historico_ativo

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


def verificar_anomalia_ml(usuario_id: int, ativo_id: int, ativo_nome: str, score_atual: int):
    historico = listar_historico_ativo(usuario_id, ativo_id, limite=50)
    scores_historicos = [h[0] for h in historico if h[0] is not None]

    if len(scores_historicos) < MINIMO_PONTOS_PARA_ML:
        e_anomalia, detalhe = _detectar_anomalia_regra_simples(scores_historicos, score_atual)
        metodo = "regra_simples"
    else:
        e_anomalia, detalhe = _detectar_anomalia_ml(scores_historicos, score_atual)
        metodo = "machine_learning"

    return e_anomalia, detalhe, metodo