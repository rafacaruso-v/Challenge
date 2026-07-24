from checkov.cloudformation.runner import Runner as CfnRunner
from checkov.terraform.runner import Runner as TfRunner
from checkov.runner_filter import RunnerFilter
import os

def rodar_checkov(caminho: str, tipo_iac: str = "cloudformation"):

    if not os.path.exists(caminho):
        return [{"criticidade": "INFO", "recurso": "Checkov", "descricao": f"Caminho não encontrado: {caminho}"}]

    runner_filter = RunnerFilter(framework=[tipo_iac])

    if tipo_iac == "terraform":
        runner = TfRunner()
    else:
        runner = CfnRunner()

    try:
        if os.path.isdir(caminho):
            report = runner.run(root_folder=caminho, runner_filter=runner_filter)
        else:
            report = runner.run(root_folder=None, files=[caminho], runner_filter=runner_filter)
    except Exception as e:
        return [{"criticidade": "INFO", "recurso": "Checkov", "descricao": f"Erro ao rodar Checkov: {e}"}]

    achados = []
    mapa_severidade = {
        "CRITICAL": "CRITICO",
        "HIGH": "ALTO",
        "MEDIUM": "MEDIO",
        "LOW": "BAIXO",
    }

    for check in report.failed_checks:
        severidade_raw = (check.severity or "MEDIUM").upper() if hasattr(check, "severity") and check.severity else "MEDIUM"
        criticidade = mapa_severidade.get(severidade_raw, "MEDIO")

        achados.append({
            "criticidade": criticidade,
            "recurso": f"IaC:{check.resource}",
            "descricao": f"{check.check_name} ({check.check_id})",
        })

    return achados