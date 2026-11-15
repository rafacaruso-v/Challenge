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

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

LIMITE_POR_SCANNER = 200
TAMANHO_MAX_ARQUIVO = 1_000_000
TAMANHO_MAX_LINHA = 5000

PASTAS_IGNORADAS = {".git", "node_modules", ".venv", "venv", "__pycache__", "reports", ".mypy_cache", ".pytest_cache"}
EXTENSOES_IGNORADAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".whl",
    ".pyc", ".woff", ".woff2", ".ttf", ".eot", ".lock", ".db", ".sqlite", ".bin", ".so", ".dll",
    ".exe", ".mp3", ".mp4",
}
ARQUIVOS_IGNORADOS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
EMAIL_DOMINIOS_IGNORADOS = ("example.com", "example.org", "example.net", "localhost", "users.noreply.github.com")
EMAIL_TLDS_IGNORADOS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "py", "json", "md", "txt", "yml", "yaml"}
ORDEM_SEVERIDADE = {"CRITICAL": 0, "ERROR": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

CPF_RE = re.compile(r"(?<!\d)(\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
CNPJ_RE = re.compile(r"(?<!\d)(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)")
CARTAO_RE = re.compile(r"(?<![\d-])(\d(?:[ -]?\d){12,18})(?![\d-])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_AUSENTE = object()


def ler_json(caminho):
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return _AUSENTE


def limitar(achados, chave_severidade=None):
    if chave_severidade:
        achados = sorted(achados, key=lambda a: ORDEM_SEVERIDADE.get(str(a.get(chave_severidade, "")).upper(), 9))
    return achados[:LIMITE_POR_SCANNER], max(0, len(achados) - LIMITE_POR_SCANNER)


def coletar_semgrep(dados):
    achados = []
    for r in (dados or {}).get("results", []):
        extra = r.get("extra", {})
        achados.append({
            "check_id": r.get("check_id", "?"),
            "path": r.get("path", "?"),
            "linha": str(r.get("start", {}).get("line", "?")),
            "severidade": extra.get("severity", "INFO"),
            "mensagem": (extra.get("message") or "")[:300],
        })
    return achados


def coletar_trivy(dados):
    achados = []
    for alvo in (dados or {}).get("Results") or []:
        for v in alvo.get("Vulnerabilities") or []:
            descricao = f'{v.get("PkgName", "?")} {v.get("InstalledVersion", "")}'.strip()
            if v.get("FixedVersion"):
                descricao += f' (corrigido em {v["FixedVersion"]})'
            if v.get("Title"):
                descricao += f': {v["Title"]}'
            achados.append({
                "severidade": v.get("Severity", "UNKNOWN"),
                "titulo": v.get("VulnerabilityID", "?"),
                "descricao": descricao[:300],
            })
    return achados


def coletar_gitleaks(dados):
    achados, vistos = [], set()
    for g in dados or []:
        chave = (g.get("RuleID"), g.get("File"), g.get("StartLine"))
        if chave in vistos:
            continue
        vistos.add(chave)
        achados.append({
            "regra": g.get("RuleID", "?"),
            "arquivo": g.get("File", "?"),
            "linha": str(g.get("StartLine", "?")),
            "descricao": g.get("Description", ""),
            "segredo_mascarado": "***",
        })
    return achados


def cpf_valido(numero):
    d = [int(c) for c in numero]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for i in (9, 10):
        soma = sum(d[j] * (i + 1 - j) for j in range(i))
        if (soma * 10) % 11 % 10 != d[i]:
            return False
    return True


def cnpj_valido(numero):
    d = [int(c) for c in numero]
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for i, pesos in ((12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)), (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))):
        resto = sum(a * b for a, b in zip(d[:i], pesos)) % 11
        if (0 if resto < 2 else 11 - resto) != d[i]:
            return False
    return True


def luhn(numero):
    total = 0
    for i, c in enumerate(reversed(numero)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def cartao_valido(numero):
    if not 13 <= len(numero) <= 19 or len(set(numero)) == 1:
        return False
    if not re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6011|65)", numero):
        return False
    return luhn(numero)


def mascarar(tipo, valor):
    digitos = re.sub(r"\D", "", valor)
    if tipo == "CPF":
        return "***.***.***-" + digitos[-2:]
    if tipo == "CNPJ":
        return "**.***.***/****-" + digitos[-2:]
    if tipo == "Cartão de crédito":
        return "**** **** **** " + digitos[-4:]
    usuario, dominio = valor.split("@", 1)
    return usuario[:1] + "***@" + dominio


def encontrar_dados(linha):
    for m in CPF_RE.finditer(linha):
        if cpf_valido(re.sub(r"\D", "", m.group(1))):
            yield "CPF", m.group(1), "alta"
    for m in CNPJ_RE.finditer(linha):
        if cnpj_valido(re.sub(r"\D", "", m.group(1))):
            yield "CNPJ", m.group(1), "alta"
    for m in CARTAO_RE.finditer(linha):
        digitos = re.sub(r"\D", "", m.group(1))
        if len(digitos) == 14 and cnpj_valido(digitos):
            continue
        if cartao_valido(digitos):
            yield "Cartão de crédito", m.group(1), "alta"
    for m in EMAIL_RE.finditer(linha):
        email = m.group(0)
        dominio = email.split("@", 1)[1].lower()
        if dominio.endswith(EMAIL_DOMINIOS_IGNORADOS) or dominio.rsplit(".", 1)[-1] in EMAIL_TLDS_IGNORADOS:
            continue
        yield "E-mail", email, "media"


def varrer_dlp(raiz):
    achados, vistos = [], set()
    for pasta, subpastas, arquivos in os.walk(raiz):
        subpastas[:] = [p for p in subpastas if p not in PASTAS_IGNORADAS]
        for nome in arquivos:
            caminho = Path(pasta) / nome
            if (nome in ARQUIVOS_IGNORADOS or nome.endswith(".min.js")
                    or caminho.suffix.lower() in EXTENSOES_IGNORADAS or caminho.is_symlink()):
                continue
            try:
                if caminho.stat().st_size > TAMANHO_MAX_ARQUIVO:
                    continue
                bruto = caminho.read_bytes()
            except OSError:
                continue
            if b"\x00" in bruto[:8000]:
                continue
            relativo = os.path.relpath(caminho, raiz).replace(os.sep, "/")
            for numero, linha in enumerate(bruto.decode("utf-8", errors="ignore").splitlines(), start=1):
                if len(linha) > TAMANHO_MAX_LINHA:
                    continue
                for tipo, valor, confianca in encontrar_dados(linha):
                    mascarado = mascarar(tipo, valor)
                    chave = (tipo, relativo, numero, mascarado)
                    if chave in vistos:
                        continue
                    vistos.add(chave)
                    achados.append({
                        "tipo": tipo,
                        "arquivo": relativo,
                        "linha": str(numero),
                        "valor_mascarado": mascarado,
                        "confianca": confianca,
                    })
    return achados


def enviar(url, chave_api, payload):
    corpo = json.dumps(payload).encode("utf-8")
    cabecalhos = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {chave_api}",
        "User-Agent": "aspm-ci/1.0",
        "ngrok-skip-browser-warning": "true",
    }
    ultimo_erro = "sem resposta"
    for tentativa in range(1, 4):
        try:
            req = urllib.request.Request(url, data=corpo, method="POST", headers=cabecalhos)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500:
                return e.code, e.read().decode("utf-8", "replace")[:300]
            ultimo_erro = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            ultimo_erro = str(e)
        if tentativa < 3:
            time.sleep(float(os.environ.get("ASPM_RETRY_DELAY", "5")) * tentativa)
    return None, ultimo_erro


def main():
    url = os.environ.get("ASPM_WEBHOOK_URL", "").strip()
    chave_api = os.environ.get("ASPM_API_KEY", "").strip()
    if not url or not chave_api:
        print("::error::Configure os secrets ASPM_WEBHOOK_URL e ASPM_API_KEY no repositório.")
        return 1
    if not url.startswith(("http://", "https://")):
        print("::error::ASPM_WEBHOOK_URL deve começar com http:// ou https://")
        return 1

    pasta_relatorios = Path(os.environ.get("ASPM_REPORTS_DIR", "reports"))
    raiz = Path(os.environ.get("ASPM_SCAN_ROOT", "."))
    avisos = []

    def carregar(nome, arquivo, variavel_status, coletor):
        dados = ler_json(pasta_relatorios / arquivo)
        if dados is _AUSENTE:
            status = os.environ.get(variavel_status, "desconhecido")
            avisos.append(f"{nome}: sem resultado (job: {status}); este scanner não foi considerado.")
            return []
        return coletor(dados)

    semgrep = carregar("SAST (Semgrep)", "semgrep.json", "RESULT_SEMGREP", coletar_semgrep)
    trivy = carregar("SCA (Trivy)", "trivy.json", "RESULT_TRIVY", coletar_trivy)
    gitleaks = carregar("Secrets (Gitleaks)", "gitleaks.json", "RESULT_GITLEAKS", coletar_gitleaks)
    dlp = varrer_dlp(raiz)

    total = {"semgrep": len(semgrep), "trivy": len(trivy), "gitleaks": len(gitleaks), "dlp": len(dlp)}
    semgrep, t1 = limitar(semgrep, "severidade")
    trivy, t2 = limitar(trivy, "severidade")
    gitleaks, t3 = limitar(gitleaks)
    dlp, t4 = limitar(dlp)

    servidor = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repositorio = os.environ.get("GITHUB_REPOSITORY", "desconhecido/desconhecido")
    sha = os.environ.get("GITHUB_SHA", "")
    partes = [
        f"Scan automático disparado por push (commit {sha[:7]}, branch {os.environ.get('GITHUB_REF_NAME', '?')}, "
        f"autor {os.environ.get('GITHUB_ACTOR', '?')}). Commit: {servidor}/{repositorio}/commit/{sha}.",
        f"Achados: SAST {total['semgrep']}, SCA {total['trivy']}, Secrets {total['gitleaks']}, DLP {total['dlp']}.",
    ]
    if t1 or t2 or t3 or t4:
        partes.append(f"Aviso: o envio foi limitado a {LIMITE_POR_SCANNER} achados por scanner, priorizando os mais graves.")
    partes.extend(avisos)

    payload = {
        "repositorio": repositorio,
        "ambiente": os.environ.get("ASPM_AMBIENTE", "Produção"),
        "pr_url": f"{servidor}/{repositorio}",
        "resumo_ia": " ".join(partes),
        "achados_semgrep": semgrep,
        "achados_trivy": trivy,
        "achados_checkov": [],
        "achados_gitleaks": gitleaks,
        "achados_dlp": dlp,
    }

    print(f"Enviando: SAST={total['semgrep']} SCA={total['trivy']} Secrets={total['gitleaks']} DLP={total['dlp']}")
    for aviso in avisos:
        print(f"::warning::{aviso}")

    status, resposta = enviar(url, chave_api, payload)
    if status == 200:
        print(f"Enviado com sucesso: {json.dumps(resposta, ensure_ascii=False)}")
        return 0
    if status is None:
        print(f"::warning::ASPM Platform indisponível ({resposta}). Os resultados não foram enviados.")
        return 0
    print(f"::error::Webhook recusou o envio (HTTP {status}): {resposta}")
    return 1


if __name__ == "__main__":
    sys.exit(main())