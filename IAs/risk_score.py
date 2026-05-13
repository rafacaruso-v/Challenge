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

        score += 10

    elif tipo == "Aplicação":

        score += 8

    elif tipo == "Repositório":

        score += 5

    # =====================================
    # AMBIENTE
    # =====================================

    if ambiente == "Produção":

        score += 20

    elif ambiente == "Homologação":

        score += 10

    elif ambiente == "Desenvolvimento":

        score += 5

    # =====================================
    # SAST
    # =====================================

    if resultado_sast:

        # Se vier lista
        if isinstance(resultado_sast, list):

            quantidade_sast = len(
                resultado_sast
            )

        else:

            quantidade_sast = 1

        score += quantidade_sast * 10

    # =====================================
    # DAST
    # =====================================

    if resultado_dast:

        # Evita contar erro do ZAP
        if (
            resultado_dast
            != "ERRO_PROXY_ZAP"
        ):

            # Se vier lista
            if isinstance(
                resultado_dast,
                list
            ):

                quantidade_dast = len(
                    resultado_dast
                )

            else:

                quantidade_dast = 1

            score += (
                quantidade_dast * 15
            )

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
