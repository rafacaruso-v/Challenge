import subprocess
import json
import os

def rodar_semgrep(caminho):
    try:
        
        if not os.path.exists(caminho):
            return "ERRO: Caminho do repositório não encontrado."

        resultado = subprocess.run(
            ["semgrep", "--config=auto", "--json", caminho],
            capture_output=True,
            text=True,
            check=False
        )

        
        if resultado.returncode != 0 and not resultado.stdout:
            return f"Erro técnico no Semgrep: {resultado.stderr}"

        try:
            dados = json.loads(resultado.stdout)
            return json.dumps(dados.get("results", []), indent=2)
        except json.JSONDecodeError:
            return resultado.stdout

    except FileNotFoundError:
        return "ERRO: O executável do Semgrep não foi encontrado. Certifique-se de que ele está instalado e no PATH do sistema."
    except Exception as e:
        return f"Erro inesperado: {str(e)}"
