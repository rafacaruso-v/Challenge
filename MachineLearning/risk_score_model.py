import numpy as np
from sklearn.ensemble import RandomForestRegressor

_MODELO = None


def _gerar_dataset_sintetico(n=3000, seed=42):
    rng = np.random.default_rng(seed)
    X = []
    y = []

    for _ in range(n):
        n_critico = rng.poisson(0.4)
        n_alto = rng.poisson(1.2)
        n_medio = rng.poisson(2.0)
        n_baixo = rng.poisson(2.5)
        ambiente_prod = rng.choice([0, 1], p=[0.6, 0.4])

        if n_critico > 0:
            base = 90 + min(n_critico * 2, 10)
        elif n_alto > 0:
            base = 70 + min(n_alto * 4, 19)
        elif n_medio > 0:
            base = 40 + min(n_medio * 7, 29)
        elif n_baixo > 0:
            base = 1 + min(n_baixo * 6, 38)
        else:
            base = 0

        if ambiente_prod and (n_critico > 0 or n_alto > 0):
            base = min(100, base + 3)

        ruido = rng.normal(0, 2)
        score_final = max(0, min(100, base + ruido))

        X.append([n_critico, n_alto, n_medio, n_baixo, ambiente_prod])
        y.append(score_final)

    return np.array(X), np.array(y)


def _obter_modelo():
    global _MODELO
    if _MODELO is None:
        X, y = _gerar_dataset_sintetico()
        _MODELO = RandomForestRegressor(n_estimators=200, max_depth=8, random_state=42)
        _MODELO.fit(X, y)
    return _MODELO


def calcular_score_ml(n_critico: int, n_alto: int, n_medio: int, n_baixo: int, ambiente: str) -> int:
    if n_critico == 0 and n_alto == 0 and n_medio == 0 and n_baixo == 0:
        return 0

    ambiente_prod = 1 if ambiente == "Produção" else 0
    modelo = _obter_modelo()

    entrada = np.array([[n_critico, n_alto, n_medio, n_baixo, ambiente_prod]])
    score = modelo.predict(entrada)[0]

    return int(round(max(0, min(100, score))))


def criticidade_por_score(score: int) -> str:
    if score >= 90:
        return "Crítica"
    elif score >= 70:
        return "Alta"
    elif score >= 40:
        return "Média"
    elif score >= 1:
        return "Baixa"
    return "Baixa"