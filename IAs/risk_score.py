def calcular_criticidade(
    tipo,
    ambiente,
    resultado_sast,
    resultado_dast
):

    score = 0

    # =====================================
    # TIPO DO ATIVO
    # =====================================

    if tipo == "API":

        score += 30

    elif tipo == "Aplicação":

        score += 25

    elif tipo == "Repositório":

        score += 15

    # =====================================
    # AMBIENTE
    # =====================================

    if ambiente == "Produção":

        score += 40

    elif ambiente == "Homologação":

        score += 20

    elif ambiente == "Desenvolvimento":

        score += 10

    # =====================================
    # SAST
    # =====================================

    if resultado_sast:

        score += 20

    # =====================================
    # DAST
    # =====================================

    if (
    resultado_dast
    and resultado_dast != "ERRO_PROXY_ZAP"
    and len(resultado_dast) > 0
    ):

        score += 30

    # =====================================
    # LIMITE
    # =====================================

    if score > 100:

        score = 100

    # =====================================
    # CRITICIDADE
    # =====================================

    if score >= 80:

        criticidade = "Crítica"

    elif score >= 60:

        criticidade = "Alta"

    elif score >= 40:

        criticidade = "Média"

    else:

        criticidade = "Baixa"

    return criticidade, score
