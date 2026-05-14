import subprocess
import json
import os
import sys

def rodar_semgrep(caminho):
    try:
        print(f"🔍 [SAST] Iniciando análise em: {caminho}")
        
        if not os.path.exists(caminho):
            return "ERRO: Caminho não encontrado."

        diretorio_python = os.path.dirname(sys.executable)
        caminho_semgrep = os.path.join(diretorio_python, "Scripts", "semgrep.exe")

        if not os.path.exists(caminho_semgrep):
            caminho_semgrep = "semgrep"

        resultado = subprocess.run(
            [caminho_semgrep, "--config=auto", "--json", caminho],
            capture_output=True,
            text=True,
            check=False,
            shell=True 
        )

        if resultado.stdout.strip():
            try:
                dados = json.loads(resultado.stdout)
                resultados = dados.get("results", [])
                print(f"✅ [SAST] Sucesso! Encontrados {len(resultados)} alertas.")
                return json.dumps(resultados, indent=2)
            except json.JSONDecodeError:
                return resultado.stdout
        
        if resultado.stderr:
            # Se ainda der erro de "não reconhecido", vamos avisar o que fazer
            if "não é reconhecido" in resultado.stderr or "not found" in resultado.stderr:
                return "ERRO: O Windows não achou o Semgrep. Rode 'pip install semgrep' no terminal e reinicie o VS Code."
            return f"Erro técnico no Semgrep: {resultado.stderr}"

        return "[]"

    except Exception as e:
        return f"Erro inesperado: {str(e)}"
