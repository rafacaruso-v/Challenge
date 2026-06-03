import subprocess
import json
import os
import shutil

def rodar_trivy(caminho_ou_url):

    caminho_local = caminho_ou_url
    clonado = False

    try:
        if caminho_ou_url.startswith("http"):
            caminho_local = "/tmp/trivy_scan_repo"

            if os.path.exists(caminho_local):
                shutil.rmtree(caminho_local)

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
                "--scanners", "vuln",
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
                vulnerabilidades = resultado_arquivo.get("Vulnerabilities") or []
                for vuln in vulnerabilidades:
                    alertas_limpos.append({
                        "package":    vuln.get("PkgName"),
                        "version":    vuln.get("InstalledVersion"),
                        "cve":        vuln.get("VulnerabilityID"),
                        "severity":   vuln.get("Severity"),
                        "fix":        vuln.get("FixedVersion", "Sem fix disponível"),
                        "title":      vuln.get("Title", ""),
                        "file":       resultado_arquivo.get("Target")
                    })

            return json.dumps(alertas_limpos, indent=2)

        return "[]"

    except subprocess.TimeoutExpired:
        return "ERRO: O scan do Trivy demorou demais e foi interrompido."
    except Exception as e:
        return f"Erro: {str(e)}"

    finally:
        # Remove o repositório clonado
        if clonado and os.path.exists(caminho_local):
            shutil.rmtree(caminho_local)