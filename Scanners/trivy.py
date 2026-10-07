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


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


def rodar_trivy(caminho_ou_url):

    caminho_local = caminho_ou_url
    clonado = False

    try:
        if caminho_ou_url.startswith("http"):
            caminho_local = "/tmp/trivy_scan_repo"

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
                "trivy", "fs",
                "--scanners", "vuln,secret,misconfig",
                "--format", "json",
                "--quiet",
                caminho_local
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if resultado.stdout:
            dados = json.loads(resultado.stdout)
            resultados = dados.get("Results", [])

            alertas_limpos = []
            for resultado_arquivo in resultados:
                arquivo_alvo = resultado_arquivo.get("Target")

                vulnerabilidades = resultado_arquivo.get("Vulnerabilities") or []
                for vuln in vulnerabilidades:
                    alertas_limpos.append({
                        "categoria":  "CVE",
                        "package":    vuln.get("PkgName"),
                        "version":    vuln.get("InstalledVersion"),
                        "cve":        vuln.get("VulnerabilityID"),
                        "severity":   vuln.get("Severity"),
                        "fix":        vuln.get("FixedVersion", "Sem fix disponível"),
                        "title":      vuln.get("Title", ""),
                        "file":       arquivo_alvo
                    })

                segredos = resultado_arquivo.get("Secrets") or []
                for segredo in segredos:
                    alertas_limpos.append({
                        "categoria":  "SECRET",
                        "package":    "",
                        "version":    "",
                        "cve":        segredo.get("RuleID", ""),
                        "severity":   segredo.get("Severity", ""),
                        "fix":        "Remover o segredo do código e revogar/rotacionar a credencial exposta",
                        "title":      f"{segredo.get('Title', 'Segredo exposto')} (linha {segredo.get('StartLine', '?')})",
                        "file":       arquivo_alvo
                    })

                misconfigs = resultado_arquivo.get("Misconfigurations") or []
                for misconfig in misconfigs:
                    alertas_limpos.append({
                        "categoria":  "MISCONFIG",
                        "package":    "",
                        "version":    "",
                        "cve":        misconfig.get("ID", ""),
                        "severity":   misconfig.get("Severity", ""),
                        "fix":        misconfig.get("Resolution", "Sem fix disponível"),
                        "title":      misconfig.get("Title", ""),
                        "file":       arquivo_alvo
                    })

            return json.dumps(alertas_limpos, indent=2)

        return "[]"

    except subprocess.TimeoutExpired:
        return "ERRO: O scan do Trivy demorou demais e foi interrompido."
    except Exception as e:
        return f"ERRO: {str(e)}"

    finally:
        if clonado and os.path.exists(caminho_local):
            shutil.rmtree(caminho_local, onerror=_forcar_remocao)
