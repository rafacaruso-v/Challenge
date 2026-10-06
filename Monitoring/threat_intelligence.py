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

import requests
from datetime import datetime, timedelta, UTC

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves_recentes(dias=7):

    agora = datetime.now(UTC)
    inicio = agora - timedelta(days=dias)

    params = {
        "pubStartDate": inicio.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": agora.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 10
    }

    try:

        resposta = requests.get(
            NVD_API,
            params=params,
            timeout=20
        )

        resposta.raise_for_status()

        dados = resposta.json()

        resultado = []

        for item in dados.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "N/A")

            descricao = ""

            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    descricao = d.get("value", "")
                    break

            score = "N/A"
            severidade = "UNKNOWN"

            metricas = cve.get("metrics", {})

            try:

                if "cvssMetricV40" in metricas:

                    cvss = metricas["cvssMetricV40"][0]["cvssData"]

                    score = cvss.get("baseScore", "N/A")
                    severidade = cvss.get("baseSeverity", "UNKNOWN")

                elif "cvssMetricV31" in metricas:

                    cvss = metricas["cvssMetricV31"][0]["cvssData"]

                    score = cvss.get("baseScore", "N/A")
                    severidade = cvss.get("baseSeverity", "UNKNOWN")

                elif "cvssMetricV30" in metricas:

                    cvss = metricas["cvssMetricV30"][0]["cvssData"]

                    score = cvss.get("baseScore", "N/A")
                    severidade = cvss.get("baseSeverity", "UNKNOWN")

                elif "cvssMetricV2" in metricas:

                    cvss = metricas["cvssMetricV2"][0]["cvssData"]

                    score = cvss.get("baseScore", "N/A")
                    severidade = metricas["cvssMetricV2"][0].get(
                        "baseSeverity",
                        "UNKNOWN"
                    )

            except Exception:
                pass

            produtos = []

            for configuracao in cve.get("configurations", []):

                for node in configuracao.get("nodes", []):

                    for cpe in node.get("cpeMatch", []):

                        criterio = cpe.get("criteria")

                        if criterio:
                            produtos.append(criterio)

            produtos = list(set(produtos))

            publicado = cve.get("published", "")

            modificado = cve.get("lastModified", "")

            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            resultado.append({

                "id": cve_id,

                "score": score,

                "severidade": severidade,

                "descricao": descricao,

                "produtos": produtos,

                "publicado": publicado,

                "ultima_modificacao": modificado,

                "url": url

            })

        return resultado

    except requests.exceptions.RequestException as e:
        return f"Erro ao consultar a API da NVD: {e}"

    except Exception as e:
        return f"Erro inesperado: {e}"
