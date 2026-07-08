import subprocess
import json
import os
import shutil
import stat


def _forcar_remocao(func, caminho, exc_info):
    os.chmod(caminho, stat.S_IWRITE)
    func(caminho)


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
                alertas_limpos.append({
                    "check_id": item.get("check_id"),
                    "path": item.get("path"),
                    "line": item.get("start", {}).get("line"),
                    "message": item.get("extra", {}).get("message"),
                    "severity": item.get("extra", {}).get("severity")
                })

            return json.dumps(alertas_limpos, indent=2)

        return "[]"

    except subprocess.TimeoutExpired:
        return "ERRO: O scan do Semgrep demorou demais e foi interrompido."
    except Exception as e:
        return f"Erro: {str(e)}"

    finally:
        if clonado and os.path.exists(caminho_local):
            shutil.rmtree(caminho_local, onerror=_forcar_remocao)