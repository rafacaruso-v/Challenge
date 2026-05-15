import subprocess
import json
import os
import sys

def rodar_semgrep(caminho):
    import subprocess
    import json
    import os

    if not os.path.exists(caminho):
        return "ERRO: Caminho não encontrado."

    try:
        resultado = subprocess.run(
            ["semgrep", "--config=auto", "--json", caminho],
            capture_output=True,
            text=True,
            check=False
        )

        if resultado.stdout:
            dados = json.loads(resultado.stdout)
            return json.dumps(dados.get("results", []), indent=2)

        return resultado.stderr or "[]"

    except Exception as e:
        return f"Erro: {str(e)}"