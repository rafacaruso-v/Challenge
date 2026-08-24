import os
import shutil
import stat
import subprocess
import tempfile
import zipfile

PASTA_UPLOADS_PERSISTENTE = "Uploads"


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


def _extrair_para_pasta(caminho_zip: str, pasta_destino: str):
    """Extrai um .zip com proteção contra Zip Slip (caminhos que tentam
    escapar da pasta de destino via ../ ou caminho absoluto)."""
    with zipfile.ZipFile(caminho_zip, "r") as zf:
        for membro in zf.namelist():
            caminho_resolvido = os.path.realpath(os.path.join(pasta_destino, membro))
            if not caminho_resolvido.startswith(os.path.realpath(pasta_destino)):
                raise RuntimeError(f"Arquivo .zip contém caminho suspeito: {membro}")
        zf.extractall(pasta_destino)


def preparar_repositorio(url: str):
    """
    Clona um repositório remoto (git) para uma pasta temporária. Único modo
    suportado para o campo de URL — não aceita mais caminho local do host,
    já que a plataforma roda em Docker e não tem acesso ao filesystem do
    usuário.
    """
    if not url.startswith("http"):
        raise RuntimeError(
            "Informe uma URL de repositório válida (iniciando com http:// ou https://), "
            "ou use a opção de upload de arquivo."
        )

    caminho_local = tempfile.mkdtemp(prefix="aspm_scan_repo_")

    try:
        clone = subprocess.run(
            ["git", "clone", "--depth=1", url, caminho_local],
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


def salvar_upload_permanente(usuario_id: int, componente_id: int, conteudo_bytes: bytes, nome_arquivo: str) -> str:
    from Database.db import salvar_upload_db
    salvar_upload_db(componente_id, nome_arquivo, conteudo_bytes)
    return f"db://uploads_componentes/{componente_id}"


def preparar_repositorio_upload(caminho_salvo: str):
    """
    Prepara um caminho local de trabalho a partir de um upload já persistido
    em disco (ver salvar_upload_permanente). Extrai .zip; arquivo único é
    apenas copiado para a pasta temporária de trabalho.
    """
    if not os.path.exists(caminho_salvo):
        raise RuntimeError(f"Arquivo do componente não encontrado: {caminho_salvo}")

    pasta_trabalho = tempfile.mkdtemp(prefix="aspm_scan_upload_")

    try:
        if caminho_salvo.lower().endswith(".zip"):
            _extrair_para_pasta(caminho_salvo, pasta_trabalho)
        else:
            nome_arquivo = os.path.basename(caminho_salvo)
            shutil.copy2(caminho_salvo, os.path.join(pasta_trabalho, nome_arquivo))
    except zipfile.BadZipFile:
        limpar_repositorio(pasta_trabalho)
        raise RuntimeError("Arquivo enviado não é um .zip válido.")

    return pasta_trabalho, True


def limpar_repositorio(caminho_local: str):
    if caminho_local and os.path.exists(caminho_local):
        shutil.rmtree(caminho_local, onerror=_forcar_remocao)