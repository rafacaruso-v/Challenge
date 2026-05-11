def calcular_criticidade(
    tipo,
    ambiente,
    resultado
):

    score = 0

    # ==================================
    # TIPO DO ATIVO
    # ==================================

    if tipo == "API":
        score += 3

    elif tipo == "Aplicação":
        score += 2

    elif tipo == "Repositório":
        score += 1

    # ==================================
    # AMBIENTE
    # ==================================

    if ambiente == "Produção":
        score += 4

    elif ambiente == "Homologação":
        score += 2

    # ==================================
    # VULNERABILIDADES
    # ==================================

    if "SQL Injection" in resultado:
        score += 5

    if "hardcoded" in resultado:
        score += 4

    if "Remote Code Execution" in resultado:
        score += 5

    # ==================================
    # CLASSIFICAÇÃO FINAL
    # ==================================

    if score >= 9:
        return "Crítica", score

    elif score >= 6:
        return "Alta", score

    elif score >= 3:
        return "Média", score

    return "Baixa", score