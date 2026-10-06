#Script rodado pela GitHub Action quando um Pull Request e MERGEADO na main (evento "push" na branch main).

import os
import re
import sys
import json
import shutil
import subprocess

import requests

from aspm_pr_scan import (
    rodar_semgrep,
    rodar_trivy,
    gerar_resumo_gemini,
)

def rodar_gitleaks(caminho: str = "."):
    if shutil.which("gitleaks") is None:
        print("[aviso] Gitleaks nao encontrado no PATH — pulando deteccao de credenciais.")
        return []

    try:
        resultado = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", caminho,
                "--no-git",
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--exit-code", "0",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception as e:
        print(f"[Aviso] Falha ao executar o Gitleaks: {e}")
        return []

    saida = resultado.stdout.strip()
    if not saida:
        return []

    try:
        achados_brutos = json.loads(saida)
    except json.JSONDecodeError:
        print(f"[Aviso] Nao foi possivel interpretar a saida do Gitleaks: {saida[:300]}")
        return []

    achados = []
    for a in achados_brutos:
        achados.append({
            "regra": a.get("RuleID", "regra-desconhecida"),
            "arquivo": a.get("File", "?"),
            "linha": a.get("StartLine", "?"),
            "descricao": a.get("Description", "Credencial exposta detectada."),
            "segredo_mascarado": _mascarar_segredo(a.get("Secret", "")),
        })

    return achados


def _mascarar_segredo(segredo: str) -> str:
    if not segredo:
        return "***"
    if len(segredo) <= 8:
        return "*" * len(segredo)
    return f"{segredo[:4]}{'*' * (len(segredo) - 8)}{segredo[-4:]}"

_PADROES_ARQUIVOS_TESTE = re.compile(
    r"(test|tests|fixture|fixtures|mock|mocks|spec|specs|__fixtures__|sample|examples?)",
    re.IGNORECASE,
)
_EXTENSOES_IGNORADAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".lock",
}
_TAMANHO_MAXIMO_ARQUIVO_BYTES = 2 * 1024 * 1024

_REGEX_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_REGEX_CNPJ = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
_REGEX_CARTAO = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _validar_cpf(cpf: str) -> bool:
    cpf = re.sub(r"\D", "", cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    dv1 = (soma * 10 % 11) % 10
    if dv1 != int(cpf[9]):
        return False
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    dv2 = (soma * 10 % 11) % 10
    return dv2 == int(cpf[10])


def _validar_cnpj(cnpj: str) -> bool:
    cnpj = re.sub(r"\D", "", cnpj)
    if len(cnpj) != 14 or cnpj == cnpj[0] * 14:
        return False

    def _dv(base, pesos):
        soma = sum(int(d) * p for d, p in zip(base, pesos))
        resto = soma % 11
        return 0 if resto < 2 else 11 - resto

    dv1 = _dv(cnpj[:12], [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    if dv1 != int(cnpj[12]):
        return False
    dv2 = _dv(cnpj[:13], [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    return dv2 == int(cnpj[13])


def _validar_luhn(numero: str) -> bool:
    numero = re.sub(r"\D", "", numero)
    if not (13 <= len(numero) <= 19):
        return False
    soma = 0
    for i, digito in enumerate(numero[::-1]):
        d = int(digito)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        soma += d
    return soma % 10 == 0


def _mascarar(valor: str, manter_inicio: int = 3, manter_fim: int = 2) -> str:
    limpo = re.sub(r"\D", "", valor)
    if len(limpo) <= manter_inicio + manter_fim:
        return "*" * len(limpo)
    return f"{limpo[:manter_inicio]}{'*' * (len(limpo) - manter_inicio - manter_fim)}{limpo[-manter_fim:]}"


def _mascarar_email(email: str) -> str:
    try:
        usuario, dominio = email.split("@", 1)
    except ValueError:
        return "***"
    if len(usuario) <= 2:
        return f"{'*' * len(usuario)}@{dominio}"
    return f"{usuario[0]}{'*' * (len(usuario) - 2)}{usuario[-1]}@{dominio}"


def _e_arquivo_de_teste(caminho: str) -> bool:
    return bool(_PADROES_ARQUIVOS_TESTE.search(caminho))


def rodar_dlp(caminho: str = "."):
    achados = []

    for raiz, dirs, arquivos in os.walk(caminho):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", "venv", ".venv")]
        for nome in arquivos:
            _, ext = os.path.splitext(nome)
            if ext.lower() in _EXTENSOES_IGNORADAS:
                continue

            caminho_arquivo = os.path.join(raiz, nome)
            try:
                if os.path.getsize(caminho_arquivo) > _TAMANHO_MAXIMO_ARQUIVO_BYTES:
                    continue
            except OSError:
                continue

            caminho_relativo = os.path.relpath(caminho_arquivo, caminho)
            e_teste = _e_arquivo_de_teste(caminho_relativo)

            try:
                with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
                    linhas = f.readlines()
            except Exception:
                continue

            for numero_linha, linha in enumerate(linhas, start=1):

                for match in _REGEX_CPF.finditer(linha):
                    if _validar_cpf(match.group()):
                        achados.append({
                            "tipo": "CPF", "arquivo": caminho_relativo, "linha": numero_linha,
                            "valor_mascarado": _mascarar(match.group()),
                            "confianca": "media" if e_teste else "alta",
                        })

                for match in _REGEX_CNPJ.finditer(linha):
                    if _validar_cnpj(match.group()):
                        achados.append({
                            "tipo": "CNPJ", "arquivo": caminho_relativo, "linha": numero_linha,
                            "valor_mascarado": _mascarar(match.group()),
                            "confianca": "media" if e_teste else "alta",
                        })

                for match in _REGEX_CARTAO.finditer(linha):
                    digitos = re.sub(r"\D", "", match.group())
                    if len(digitos) >= 13 and _validar_luhn(digitos):
                        achados.append({
                            "tipo": "Cartao_Credito", "arquivo": caminho_relativo, "linha": numero_linha,
                            "valor_mascarado": _mascarar(match.group(), manter_inicio=4, manter_fim=4),
                            "confianca": "media" if e_teste else "alta",
                        })

                for match in _REGEX_EMAIL.finditer(linha):
                    achados.append({
                        "tipo": "Email", "arquivo": caminho_relativo, "linha": numero_linha,
                        "valor_mascarado": _mascarar_email(match.group()),
                        "confianca": "media",
                    })

    return achados

def _transformar_semgrep(achados_brutos: list) -> list:
    transformados = []
    for a in achados_brutos:
        transformados.append({
            "check_id": a.get("check_id", "?"),
            "path": a.get("path", "?"),
            "linha": str(a.get("start", {}).get("line", "?")),
            "severidade": a.get("extra", {}).get("severity", "INFO"),
            "mensagem": a.get("extra", {}).get("message", ""),
        })
    return transformados


def _transformar_trivy(achados_brutos: list) -> list:
    return [
        {
            "severidade": a.get("severidade", "UNKNOWN"),
            "titulo": a.get("titulo", "?"),
            "descricao": a.get("descricao", ""),
        }
        for a in achados_brutos
    ]


def _transformar_gitleaks(achados_brutos: list) -> list:
    return [
        {
            "regra": a.get("regra", "?"),
            "arquivo": a.get("arquivo", "?"),
            "linha": str(a.get("linha", "?")),
            "descricao": a.get("descricao", ""),
            "segredo_mascarado": a.get("segredo_mascarado", "***"),
        }
        for a in achados_brutos
    ]


def _transformar_dlp(achados_brutos: list) -> list:
    return [
        {
            "tipo": a.get("tipo", "?"),
            "arquivo": a.get("arquivo", "?"),
            "linha": str(a.get("linha", "?")),
            "valor_mascarado": a.get("valor_mascarado", "***"),
            "confianca": a.get("confianca", "media"),
        }
        for a in achados_brutos
    ]


def enviar_para_aspm(
    achados_semgrep, achados_trivy,
    achados_gitleaks, achados_dlp, resumo_ia
):
    webhook_url = os.environ.get("ASPM_WEBHOOK_URL", "").strip()
    api_key = os.environ.get("ASPM_API_KEY", "").strip()
    repo = os.environ.get("REPO", "").strip()

    if not webhook_url or not api_key:
        print("[info] ASPM_WEBHOOK_URL ou ASPM_API_KEY não configurados — pulando envio para a plataforma.")
        return

    payload = {
        "repositorio": repo,
        "ambiente": "Produção",
        "pr_url": f"https://github.com/{repo}",
        "resumo_ia": resumo_ia,
        "achados_semgrep": _transformar_semgrep(achados_semgrep),
        "achados_trivy": _transformar_trivy(achados_trivy),
        "achados_gitleaks": _transformar_gitleaks(achados_gitleaks),
        "achados_dlp": _transformar_dlp(achados_dlp),
    }

    url = webhook_url.rstrip("/") + "/webhook/pr-scan"
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        resposta = requests.post(url, json=payload, headers=headers, timeout=30)
        resposta.raise_for_status()
        dados = resposta.json()
        print(f"[ok] Gravado na ASPM Platform: ativo_id={dados.get('ativo_id')} "
              f"(criado agora: {dados.get('ativo_criado_agora')}) | "
              f"componente_id={dados.get('componente_id')} | "
              f"criticidade={dados.get('criticidade')} | score={dados.get('score')}")
    except requests.exceptions.RequestException as e:
        print(f"[erro] Falha ao enviar para a ASPM Platform: {e}", file=sys.stderr)


def main():
    print("Rodando Semgrep...")
    achados_semgrep = rodar_semgrep()

    print("Rodando Trivy...")
    achados_trivy = rodar_trivy()

    print("Rodando Gitleaks...")
    achados_gitleaks = rodar_gitleaks()

    print("Rodando scanner de DLP...")
    achados_dlp = rodar_dlp()

    print("Gerando resumo executivo via Gemini (se configurado)...")
    resumo_ia = gerar_resumo_gemini(achados_semgrep, achados_trivy)

    print("Enviando resultado para a ASPM Platform...")
    enviar_para_aspm(
        achados_semgrep, achados_trivy,
        achados_gitleaks, achados_dlp, resumo_ia
    )

if __name__ == "__main__":
    main()