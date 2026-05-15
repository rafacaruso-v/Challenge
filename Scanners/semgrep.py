import subprocess
import json
import os

def rodar_semgrep(caminho):
    
    if not os.path.exists(caminho):
        return "ERRO: Caminho não encontrado localmente."

    try:
        
        resultado = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", caminho],
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
