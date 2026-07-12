from Database.db import listar_ativos_db, listar_logs
import Auth.auth as auth_module
import Database.db as db_module


def avaliar_acesso_logico():
    mfa_implementado  = hasattr(auth_module, "confirmar_mfa") and hasattr(auth_module, "mfa_pendente")
    rbac_implementado = hasattr(db_module, "atualizar_role_usuario") and hasattr(db_module, "contar_admins")

    faltando = []
    if not mfa_implementado:
        faltando.append("autenticação multifator (MFA)")
    if not rbac_implementado:
        faltando.append("controle de acesso baseado em função (RBAC)")

    if not faltando:
        return "Conforme", "Autenticação multifator e controle de acesso baseado em função implementados na plataforma."
    return "Não Conforme", f"Recurso(s) ausente(s) na plataforma: {', '.join(faltando)}."


def avaliar_mitigacao_vulnerabilidades(usuario_id):
    ativos = listar_ativos_db(usuario_id)
    if not ativos:
        return "Não Avaliado", "Nenhum ativo cadastrado na plataforma até o momento."

    total      = len(ativos)
    analisados = sum(1 for a in ativos if a[9])

    if analisados == 0:
        return "Não Conforme", f"Nenhum dos {total} ativo(s) cadastrado(s) possui análise executada."
    if analisados == total:
        return "Conforme", f"Todos os {total} ativo(s) cadastrado(s) possuem cobertura de scanner (SAST/DAST/SCA)."
    return "Parcialmente Conforme", f"{analisados} de {total} ativo(s) cadastrado(s) possuem análise executada."


def avaliar_rastreabilidade(usuario_id):
    logs = listar_logs(usuario_id, limite=1)
    if not logs:
        return "Não Conforme", "Nenhum registro de auditoria (audit trail) encontrado para este usuário."
    return "Conforme", "Audit trail ativo — ações da plataforma e alertas de segurança estão sendo registrados."


def avaliar_avaliacao_riscos(usuario_id):
    ativos = listar_ativos_db(usuario_id)
    if not ativos:
        return "Não Avaliado", "Nenhum ativo cadastrado na plataforma até o momento."

    com_score = sum(1 for a in ativos if a[7] is not None)
    if com_score == 0:
        return "Não Conforme", "Nenhum ativo possui score de risco calculado."
    return "Conforme", f"{com_score} de {len(ativos)} ativo(s) possuem score de risco calculado e classificado por criticidade."


def avaliar_plataforma(usuario_id) -> dict:

    status_acesso,    detalhe_acesso    = avaliar_acesso_logico()
    status_mitig,     detalhe_mitig     = avaliar_mitigacao_vulnerabilidades(usuario_id)
    status_rastreio,  detalhe_rastreio  = avaliar_rastreabilidade(usuario_id)
    status_risco,     detalhe_risco     = avaliar_avaliacao_riscos(usuario_id)

    return {
        "acesso_logico":              {"status": status_acesso,   "detalhe": detalhe_acesso},
        "mitigacao_vulnerabilidades": {"status": status_mitig,    "detalhe": detalhe_mitig},
        "rastreabilidade":            {"status": status_rastreio, "detalhe": detalhe_rastreio},
        "avaliacao_riscos":           {"status": status_risco,    "detalhe": detalhe_risco},
    }