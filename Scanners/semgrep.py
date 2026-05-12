import subprocess

def rodar_semgrep(caminho):

    try:

        resultado = subprocess.run(
            ["semgrep", "--config=auto", caminho],
            capture_output=True,
            text=True
        )

        return resultado.stdout

    except Exception as e:
        return str(e)
