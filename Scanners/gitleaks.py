import subprocess
import json
import os
import shutil
import tempfile


def _gitleaks_instalado() -> bool:
    return shutil.which("gitleaks") is not None

def rodar_gitleaks(caminho_repositorio: str):

    if not _gitleaks_instalado():
        return "ERRO: Gitleaks não está instalado no ambiente (binário 'gitleaks' não encontrado no PATH)."

    if not os.path.exists(caminho_repositorio):
        return f"ERRO: Caminho do repositório inválido: {caminho_repositorio}"

    with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp:
        caminho_relatorio = tmp.name

    try:
        resultado = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", caminho_repositorio,
                "--no-git",
                "--report-format", "json",
                "--report-path", caminho_relatorio,
                "--exit-code", "0",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        os.unlink(caminho_relatorio)
        return "ERRO: Gitleaks excedeu o tempo limite de execução (300s)."
    except Exception as e:
        os.unlink(caminho_relatorio)
        return f"ERRO: Falha ao executar o Gitleaks: {e}"

    try:
        with open(caminho_relatorio, "r", encoding="utf-8") as f:
            saida = f.read().strip()
    except FileNotFoundError:
        saida = ""
    finally:
        if os.path.exists(caminho_relatorio):
            os.unlink(caminho_relatorio)

    if not saida:
        return []

    try:
        achados_brutos = json.loads(saida)
    except json.JSONDecodeError:
        return f"ERRO: Não foi possível interpretar a saída do Gitleaks: {saida[:300]}"

    achados = []
    for a in achados_brutos:
        achados.append({
            "regra": a.get("RuleID", "regra-desconhecida"),
            "arquivo": a.get("File", "?"),
            "linha": a.get("StartLine", "?"),
            "descricao": a.get("Description", "Credencial exposta detectada."),
            "commit": a.get("Commit", None),
            "segredo_mascarado": _mascarar_segredo(a.get("Secret", "")),
        })

    return achados


def _mascarar_segredo(segredo: str) -> str:
    if not segredo:
        return "***"
    if len(segredo) <= 8:
        return "*" * len(segredo)
    return f"{segredo[:4]}{'*' * (len(segredo) - 8)}{segredo[-4:]}"