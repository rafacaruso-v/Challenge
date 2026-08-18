import subprocess
import json
import os
import shutil


def _gitleaks_instalado() -> bool:
    return shutil.which("gitleaks") is not None

def rodar_gitleaks(caminho_repositorio: str):
    
    if not _gitleaks_instalado():
        return "ERRO: Gitleaks não está instalado no ambiente (binário 'gitleaks' não encontrado no PATH)."

    if not os.path.isdir(caminho_repositorio):
        return f"ERRO: Caminho do repositório inválido: {caminho_repositorio}"

    try:
        resultado = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", caminho_repositorio,
                "--no-git",
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--exit-code", "0",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return "ERRO: Gitleaks excedeu o tempo limite de execução (300s)."
    except Exception as e:
        return f"ERRO: Falha ao executar o Gitleaks: {e}"

    saida = resultado.stdout.strip()
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
    """
    NUNCA expõe a credencial completa em relatórios, logs, ou no prompt
    enviado para a IA — isso seria vazar o segredo de novo, só que através
    da própria ferramenta de segurança. Mostra só os primeiros/últimos
    caracteres, como qualquer ferramenta de mercado (GitGuardian, GitHub
    Secret Scanning, etc.) faz.
    """
    if not segredo:
        return "***"
    if len(segredo) <= 8:
        return "*" * len(segredo)
    return f"{segredo[:4]}{'*' * (len(segredo) - 8)}{segredo[-4:]}"