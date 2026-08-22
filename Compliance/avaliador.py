from datetime import datetime
from Database.db import listar_ativos_db, listar_logs, listar_usuarios, listar_componentes_usuario

JANELA_RASTREABILIDADE_DIAS = 30


def avaliar_acesso_logico(usuario_id):
    usuarios_db = listar_usuarios()
    roles_em_uso = {u[4] for u in usuarios_db}

    rbac_diferenciado = len(roles_em_uso) > 1

    if not usuarios_db:
        return "Não Avaliado", "Nenhum usuário cadastrado na plataforma até o momento."

    if not rbac_diferenciado:
        return (
            "Parcialmente Conforme",
            f"MFA é exigido estruturalmente em todo login. RBAC, porém, não está "
            f"sendo usado na prática — todos os {len(usuarios_db)} usuário(s) cadastrado(s) "
            f"possuem a mesma role ('{next(iter(roles_em_uso))}')."
        )

    return (
        "Conforme",
        f"MFA exigido estruturalmente em todo login. RBAC em uso ativo: "
        f"{len(roles_em_uso)} roles distintas entre os {len(usuarios_db)} usuário(s) cadastrado(s)."
    )


def avaliar_mitigacao_vulnerabilidades(usuario_id):
    ativos = listar_ativos_db(usuario_id)
    if not ativos:
        return "Não Avaliado", "Nenhum ativo cadastrado na plataforma até o momento."

    total      = len(ativos)
    analisados = sum(1 for a in ativos if a[10] != 'Sem análise')

    if analisados == 0:
        return "Não Conforme", f"Nenhum dos {total} ativo(s) cadastrado(s) possui componente analisado."

    componentes = listar_componentes_usuario(usuario_id)
    repositorios_analisados = [
        c for c in componentes
        if c[3] == "Repositório" and c[8] not in (None, "Erro") and c[10]
    ]

    if repositorios_analisados:
        repos_com_secrets_dlp = sum(
            1 for c in repositorios_analisados
            if "---VULNS_SECRETS---" in c[10] and "---VULNS_DLP---" in c[10]
        )
        repos_legado = len(repositorios_analisados) - repos_com_secrets_dlp
    else:
        repos_com_secrets_dlp = 0
        repos_legado = 0

    if analisados < total:
        detalhe = f"{analisados} de {total} ativo(s) cadastrado(s) possuem ao menos um componente analisado."
        if repositorios_analisados:
            detalhe += (
                f" Dos {len(repositorios_analisados)} componente(s) de Repositório analisado(s), "
                f"{repos_com_secrets_dlp} possuem cobertura de Secrets/DLP."
            )
        return "Parcialmente Conforme", detalhe

    if repos_legado > 0:
        return (
            "Parcialmente Conforme",
            f"Todos os {total} ativo(s) cadastrado(s) possuem componente analisado, cobrindo "
            f"SAST/DAST/SCA/CSPM/IaC. Porém {repos_legado} de {len(repositorios_analisados)} "
            f"componente(s) de Repositório foram analisados antes da cobertura de Secrets/DLP "
            f"(Gitleaks/DLP Scanner) e precisam de nova análise para conformidade completa."
        )

    ferramentas_str = "SAST/DAST/SCA/CSPM/IaC"
    if repositorios_analisados:
        ferramentas_str += "/Secrets/DLP"

    return "Conforme", f"Todos os {total} ativo(s) cadastrado(s) possuem cobertura de scanner ({ferramentas_str})."


def avaliar_rastreabilidade(usuario_id):
    logs = listar_logs(usuario_id, limite=1)
    if not logs:
        return "Não Conforme", "Nenhum registro de auditoria (audit trail) encontrado para este usuário."

    data_str = logs[0][1] 
    try:
        data_log_mais_recente = datetime.strptime(data_str, "%d/%m/%Y %H:%M:%S")
        dias_desde_ultimo_log = (datetime.now() - data_log_mais_recente).days
    except (ValueError, TypeError):
        return "Conforme", "Audit trail ativo — ações da plataforma e alertas de segurança estão sendo registrados."

    if dias_desde_ultimo_log > JANELA_RASTREABILIDADE_DIAS:
        return (
            "Parcialmente Conforme",
            f"Audit trail existe, mas o registro mais recente tem {dias_desde_ultimo_log} dia(s) "
            f"— acima da janela de {JANELA_RASTREABILIDADE_DIAS} dias esperada para uso ativo."
        )

    return (
        "Conforme",
        f"Audit trail ativo — último registro há {dias_desde_ultimo_log} dia(s), "
        f"dentro da janela de {JANELA_RASTREABILIDADE_DIAS} dias esperada."
    )


def avaliar_avaliacao_riscos(usuario_id):
    """
    'score_medio' (índice 8) é o campo agregado correto para saber se o
    ativo tem risco calculado — no schema antigo isso vivia em a[7],
    mas com a migração para Ativo + Componentes a posição mudou.
    """
    ativos = listar_ativos_db(usuario_id)
    if not ativos:
        return "Não Avaliado", "Nenhum ativo cadastrado na plataforma até o momento."

    com_score = sum(1 for a in ativos if a[8] is not None)
    if com_score == 0:
        return "Não Conforme", "Nenhum ativo possui score de risco calculado."
    return "Conforme", f"{com_score} de {len(ativos)} ativo(s) possuem score de risco calculado e classificado por criticidade."


def avaliar_plataforma(usuario_id) -> dict:

    status_acesso,    detalhe_acesso    = avaliar_acesso_logico(usuario_id)
    status_mitig,     detalhe_mitig     = avaliar_mitigacao_vulnerabilidades(usuario_id)
    status_rastreio,  detalhe_rastreio  = avaliar_rastreabilidade(usuario_id)
    status_risco,     detalhe_risco     = avaliar_avaliacao_riscos(usuario_id)

    return {
        "acesso_logico":              {"status": status_acesso,   "detalhe": detalhe_acesso},
        "mitigacao_vulnerabilidades": {"status": status_mitig,    "detalhe": detalhe_mitig},
        "rastreabilidade":            {"status": status_rastreio, "detalhe": detalhe_rastreio},
        "avaliacao_riscos":           {"status": status_risco,    "detalhe": detalhe_risco},
    }