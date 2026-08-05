import os
import shutil
import stat
import subprocess
import tempfile


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


def preparar_repositorio(url_ou_caminho: str):
    """
    Resolve um unico caminho local para o repositorio, clonando apenas UMA
    vez se 'url_ou_caminho' for uma URL remota. Usado para compartilhar o
    mesmo clone entre SAST (Semgrep), SCA (Trivy) e IaC (Checkov), evitando
    3 clones separados do mesmo repositorio a cada analise.
    """
    
    if not url_ou_caminho.startswith("http"):
        return url_ou_caminho, False

    caminho_local = tempfile.mkdtemp(prefix="aspm_scan_repo_")

    try:
        clone = subprocess.run(
            ["git", "clone", "--depth=1", url_ou_caminho, caminho_local],
            capture_output=True,
            text=True,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        limpar_repositorio(caminho_local)
        raise RuntimeError("O clone do repositório demorou demais e foi interrompido.")

    if clone.returncode != 0:
        limpar_repositorio(caminho_local)
        raise RuntimeError(f"Falha ao clonar repositório: {clone.stderr}")

    return caminho_local, True


def limpar_repositorio(caminho_local: str):
    if caminho_local and os.path.exists(caminho_local):
        shutil.rmtree(caminho_local, onerror=_forcar_remocao)