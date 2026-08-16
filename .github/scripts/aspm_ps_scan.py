"""
Script rodado pela GitHub Action quando um Pull Request e MERGEADO na
main (evento "push" na branch main).

Diferente do aspm_pr_scan.py (que so comenta no PR, sem tocar no banco),
este script REPRESENTA O ESTADO OFICIAL do repositorio -- por isso, alem
de rodar os mesmos scanners, ele envia o resultado para a API da ASPM
Platform, que grava no banco (criando o Ativo automaticamente se for a
primeira vez, ou atualizando o Componente existente).

Variaveis de ambiente esperadas:
- GEMINI_KEY_1     : para o resumo executivo (opcional)
- ASPM_WEBHOOK_URL : URL da API da ASPM (ex: https://xxxx.ngrok-free.app)
- ASPM_API_KEY     : API Key gerada na plataforma, identifica o usuario
- REPO             : "owner/nome-do-repo" (github.repository)
"""

import os
import sys

import requests

from aspm_pr_scan import (
    rodar_semgrep,
    rodar_trivy,
    rodar_checkov,
    gerar_resumo_gemini,
)


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


def _transformar_checkov(achados_brutos: list) -> list:
    return [
        {
            "check_id": a.get("check_id", "?"),
            "check_name": a.get("check_name", "?"),
            "recurso": a.get("recurso", "?"),
            "arquivo": a.get("arquivo", "?"),
        }
        for a in achados_brutos
    ]


def enviar_para_aspm(achados_semgrep, achados_trivy, achados_checkov, resumo_ia):
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
        "achados_checkov": _transformar_checkov(achados_checkov),
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

    print("Rodando Checkov...")
    achados_checkov = rodar_checkov()

    print("Gerando resumo executivo via Gemini (se configurado)...")
    resumo_ia = gerar_resumo_gemini(achados_semgrep, achados_trivy, achados_checkov)

    print("Enviando resultado para a ASPM Platform...")
    enviar_para_aspm(achados_semgrep, achados_trivy, achados_checkov, resumo_ia)


if __name__ == "__main__":
    main()