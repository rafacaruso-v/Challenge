import requests
from datetime import datetime, timedelta

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def buscar_cves_recentes(dias=7):

    agora = datetime.utcnow()
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