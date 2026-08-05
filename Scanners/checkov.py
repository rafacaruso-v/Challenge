import os
import shutil
import stat
import subprocess
from checkov.cloudformation.runner import Runner as CfnRunner
from checkov.terraform.runner import Runner as TfRunner
from checkov.runner_filter import RunnerFilter


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


_MARCADORES_CLOUDFORMATION = (
    "AWSTemplateFormatVersion",
    "Transform: AWS::Serverless",
)


def _arquivo_e_cloudformation(caminho_arquivo: str) -> bool:
    try:
        with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
            conteudo = f.read()
    except OSError:
        return False

    if any(marcador in conteudo for marcador in _MARCADORES_CLOUDFORMATION):
        return True

    return "Resources:" in conteudo and "Type: AWS::" in conteudo


def _detectar_tipos_iac(caminho_local: str) -> set:
    tipos_encontrados = set()

    if os.path.isfile(caminho_local):
        if caminho_local.endswith(".tf") or caminho_local.endswith(".tf.json"):
            tipos_encontrados.add("terraform")
        elif caminho_local.endswith((".yaml", ".yml", ".json")):
            if _arquivo_e_cloudformation(caminho_local):
                tipos_encontrados.add("cloudformation")
        return tipos_encontrados

    for raiz, dirs, arquivos in os.walk(caminho_local):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".terraform", "__pycache__")]

        for nome_arquivo in arquivos:
            caminho_completo = os.path.join(raiz, nome_arquivo)

            if nome_arquivo.endswith(".tf") or nome_arquivo.endswith(".tf.json"):
                tipos_encontrados.add("terraform")
            elif nome_arquivo.endswith((".yaml", ".yml", ".json")):
                if _arquivo_e_cloudformation(caminho_completo):
                    tipos_encontrados.add("cloudformation")

        if tipos_encontrados == {"terraform", "cloudformation"}:
            break

    return tipos_encontrados


def _rodar_runner(caminho_local: str, tipo_iac: str) -> list:
    """
    Roda o Checkov para um framework especifico (terraform/cloudformation) e
    retorna os achados SEM classificacao de severidade.

    A severidade e responsabilidade da camada de IA (LLMs/gemini.py), que ja
    consolida e classifica (Critico/Alto/Medio/Baixo) os achados de todos os
    scanners (Semgrep, Trivy, Checkov) de forma unificada. Isso evita manter
    um mapa de severidades local desatualizavel e evita depender da API paga
    da plataforma Bridgecrew/Prisma Cloud (que retorna 403 sem uma conta/API
    key vinculada e nao possui mais self-signup gratuito).

    Cada achado carrega um bloco "contexto_ia" com metadados que o proprio
    Checkov ja preenche localmente (sem chamada externa), como o link do
    guideline e a categoria do check (ex: IAM, Networking, Encryption),
    que servem de sinal para a IA classificar a severidade com mais precisao.
    """
    runner_filter = RunnerFilter(framework=[tipo_iac])
    runner = TfRunner() if tipo_iac == "terraform" else CfnRunner()

    try:
        if os.path.isdir(caminho_local):
            report = runner.run(root_folder=caminho_local, runner_filter=runner_filter)
        else:
            report = runner.run(root_folder=None, files=[caminho_local], runner_filter=runner_filter)
    except Exception as e:
        return [{
            "recurso": "Checkov",
            "descricao": f"Erro ao rodar Checkov ({tipo_iac}): {e}",
            "contexto_ia": None,
        }]

    achados = []
    for check in report.failed_checks:
        achados.append({
            "recurso": f"IaC:{check.resource}",
            "descricao": f"{check.check_name} ({check.check_id})",
            "contexto_ia": {
                "check_id": check.check_id,
                "check_name": check.check_name,
                "resource": check.resource,
                "file_path": getattr(check, "file_path", None),
                "file_line_range": getattr(check, "file_line_range", None),
                "guideline": getattr(check, "guideline", None),
                "bc_category": getattr(check, "bc_category", None),
            },
        })

    return achados


def rodar_checkov(caminho_ou_url, tipo_iac: str = None):
    caminho_local = caminho_ou_url
    clonado = False

    try:
        if caminho_ou_url.startswith("http"):
            caminho_local = "/tmp/checkov_scan_repo"

            if os.path.exists(caminho_local):
                shutil.rmtree(caminho_local, onerror=_forcar_remocao)

            clone = subprocess.run(
                ["git", "clone", "--depth=1", caminho_ou_url, caminho_local],
                capture_output=True,
                text=True,
                timeout=60
            )

            if clone.returncode != 0:
                return [{"recurso": "Checkov", "descricao": f"Falha ao clonar repositorio: {clone.stderr}", "contexto_ia": None}]

            clonado = True

        if not os.path.exists(caminho_local):
            return [{"recurso": "Checkov", "descricao": f"Caminho nao encontrado: {caminho_local}", "contexto_ia": None}]

        if tipo_iac is not None:
            return _rodar_runner(caminho_local, tipo_iac)

        tipos_detectados = _detectar_tipos_iac(caminho_local)

        if not tipos_detectados:
            return []

        achados = []
        for tipo in tipos_detectados:
            achados += _rodar_runner(caminho_local, tipo)

        return achados

    except subprocess.TimeoutExpired:
        return [{"recurso": "Checkov", "descricao": "O clone do repositorio demorou demais e foi interrompido.", "contexto_ia": None}]
    except Exception as e:
        return [{"recurso": "Checkov", "descricao": f"Erro inesperado: {e}", "contexto_ia": None}]

    finally:
        if clonado and os.path.exists(caminho_local):
            shutil.rmtree(caminho_local, onerror=_forcar_remocao)