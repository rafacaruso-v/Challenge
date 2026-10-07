# ASPM Platform - Application Security Posture Management (ASPM) platform that centralizes asset discovery, security scanning (SAST, DAST, SCA, IaC, CSPM, Secrets, DLP), and security findings, consolidating everything into a single application/business risk dashboard.
#
# Copyright (C) 2026 Guilherme Monteiro, Rafael Caruso, João Pedro
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import subprocess
import json
import os
import shutil
import stat
import ast

try:
    from tree_sitter_language_pack import get_parser
except ImportError:
    get_parser = None


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


def _encontrar_bloco_funcao_ast(codigo_fonte: str, linha_alvo: int):
    try:
        arvore = ast.parse(codigo_fonte)
    except SyntaxError:
        return None

    melhor_no = None

    for no in ast.walk(arvore):
        if isinstance(no, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inicio = getattr(no, "lineno", None)
            fim = getattr(no, "end_lineno", None)
            if inicio is None or fim is None:
                continue
            if inicio <= linha_alvo <= fim:
                if melhor_no is None:
                    melhor_no = no
                else:
                    span_atual  = melhor_no.end_lineno - melhor_no.lineno
                    span_novo   = fim - inicio
                    if span_novo < span_atual:
                        melhor_no = no

    if melhor_no is None:
        return None

    linha_inicio = melhor_no.lineno
    if melhor_no.decorator_list:
        linha_inicio = min(linha_inicio, min(d.lineno for d in melhor_no.decorator_list))

    return linha_inicio, melhor_no.end_lineno


EXTENSAO_PARA_LINGUAGEM = {
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java",
    ".php": "php",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".cs": "c_sharp",
}

TIPOS_NO_FUNCAO = {
    "javascript": {"function_declaration", "method_definition", "arrow_function", "function_expression"},
    "typescript": {"function_declaration", "method_definition", "arrow_function", "function_expression"},
    "tsx":        {"function_declaration", "method_definition", "arrow_function", "function_expression"},
    "java":       {"method_declaration", "constructor_declaration"},
    "php":        {"function_definition", "method_declaration"},
    "go":         {"function_declaration", "method_declaration"},
    "ruby":       {"method", "singleton_method"},
    "c":          {"function_definition"},
    "cpp":        {"function_definition"},
    "c_sharp":    {"method_declaration", "constructor_declaration", "local_function_statement"},
}


def _encontrar_bloco_funcao_tree_sitter(codigo_fonte: str, linguagem: str, linha_alvo: int):
    if get_parser is None:
        return None

    tipos_alvo = TIPOS_NO_FUNCAO.get(linguagem)
    if not tipos_alvo:
        return None

    try:
        parser = get_parser(linguagem)
        arvore = parser.parse(bytes(codigo_fonte, "utf8"))
    except Exception:
        return None

    linha_alvo_idx = linha_alvo - 1
    melhor_no = None

    pilha = [arvore.root_node]
    while pilha:
        no = pilha.pop()
        if no.type in tipos_alvo:
            inicio, fim = no.start_point[0], no.end_point[0]
            if inicio <= linha_alvo_idx <= fim:
                if melhor_no is None or (fim - inicio) < (melhor_no.end_point[0] - melhor_no.start_point[0]):
                    melhor_no = no
        pilha.extend(no.children)

    if melhor_no is None:
        return None

    return melhor_no.start_point[0] + 1, melhor_no.end_point[0] + 1


def _extrair_snippet(caminho_base: str, caminho_arquivo: str, linha_inicio: int, linha_fim: int, contexto: int = 4) -> str:
    if not linha_inicio:
        return ""

    caminho_completo = caminho_arquivo
    if not os.path.isabs(caminho_completo) or not os.path.exists(caminho_completo):
        caminho_completo = os.path.join(caminho_base, caminho_arquivo)

    try:
        with open(caminho_completo, "r", encoding="utf-8", errors="ignore") as f:
            linhas = f.readlines()
    except OSError:
        return ""

    linha_fim = linha_fim or linha_inicio

    _, extensao = os.path.splitext(caminho_completo)
    extensao = extensao.lower()
    codigo_fonte = "".join(linhas)

    bloco = None
    if extensao == ".py":
        bloco = _encontrar_bloco_funcao_ast(codigo_fonte, linha_inicio)
    else:
        linguagem = EXTENSAO_PARA_LINGUAGEM.get(extensao)
        if linguagem:
            bloco = _encontrar_bloco_funcao_tree_sitter(codigo_fonte, linguagem, linha_inicio)

    if bloco:
        linha_inicio_bloco, linha_fim_bloco = bloco
        inicio = max(0, linha_inicio_bloco - 1)
        fim = min(len(linhas) - 1, linha_fim_bloco - 1)
    else:
        inicio = max(0, linha_inicio - 1 - contexto)
        fim = min(len(linhas) - 1, linha_fim - 1 + contexto)

    trecho = []
    for i in range(inicio, fim + 1):
        trecho.append(f"{i + 1}: {linhas[i].rstrip()}")

    return "\n".join(trecho)


def rodar_semgrep(caminho_ou_url):

    caminho_local = caminho_ou_url
    clonado = False

    try:
        if caminho_ou_url.startswith("http"):
            caminho_local = "/tmp/semgrep_scan_repo"

            if os.path.exists(caminho_local):
                shutil.rmtree(caminho_local, onerror=_forcar_remocao)

            clone = subprocess.run(
                ["git", "clone", "--depth=1", caminho_ou_url, caminho_local],
                capture_output=True,
                text=True,
                timeout=60
            )

            if clone.returncode != 0:
                return f"ERRO: Falha ao clonar repositório. {clone.stderr}"

            clonado = True

        if not os.path.exists(caminho_local):
            return "ERRO: Caminho não encontrado localmente."

        resultado = subprocess.run(
            [
                "semgrep",
                "--config", "Regras/regras_semgrep.yaml",
                "--config=auto",
                "--config=p/secrets",
                "--config=p/flask",
                "--config=p/python",
                "--config=p/owasp-top-ten",
                "--config=p/java",
                "--config=p/javascript",
                "--config=p/cwe-top-25",
                "--json", "--quiet", caminho_local
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if resultado.stdout:
            dados = json.loads(resultado.stdout)
            achados = dados.get("results", [])

            alertas_limpos = []
            for item in achados:
                linha_inicio = item.get("start", {}).get("line")
                linha_fim    = item.get("end", {}).get("line", linha_inicio)
                caminho_item = item.get("path")

                snippet = _extrair_snippet(caminho_local, caminho_item, linha_inicio, linha_fim)

                alertas_limpos.append({
                    "check_id": item.get("check_id"),
                    "path": caminho_item,
                    "line": linha_inicio,
                    "end_line": linha_fim,
                    "message": item.get("extra", {}).get("message"),
                    "severity": item.get("extra", {}).get("severity"),
                    "snippet": snippet,
                })

            return json.dumps(alertas_limpos, indent=2, ensure_ascii=False)

        return "[]"

    except subprocess.TimeoutExpired:
        return "ERRO: O scan do Semgrep demorou demais e foi interrompido."
    except Exception as e:
        return f"ERRO: {str(e)}"

    finally:
        if clonado and os.path.exists(caminho_local):
            shutil.rmtree(caminho_local, onerror=_forcar_remocao)
