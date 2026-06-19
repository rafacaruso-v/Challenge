import time
import json
import os
import requests as req
from zapv2 import ZAPv2

def _normalizar_url(url: str) -> str:
    return url.replace("localhost", "127.0.0.1")

def _agrupar_alertas(alertas: list) -> list:
    """
    Agrupa alertas do mesmo tipo em um único item,
    listando os endpoints afetados sem repetir a descrição.
    Reduz drasticamente o volume enviado para a IA.
    """
    grupos = {}
    for a in alertas:
        nome = a.get("name", "")
        if nome not in grupos:
            grupos[nome] = {
                "name":        nome,
                "risk":        a.get("risk", ""),
                "confidence":  a.get("confidence", ""),
                "description": a.get("description", ""),
                "solution":    a.get("solution", ""),
                "endpoints":   []
            }
        url = a.get("url", "")
        if url and url not in grupos[nome]["endpoints"]:
            grupos[nome]["endpoints"].append(url)

    resultado = []
    for g in grupos.values():
        g["endpoints"] = g["endpoints"][:3]
        resultado.append(g)

    return resultado

def _aguardar_zap(zap_url: str, tentativas: int = 8, intervalo: int = 3) -> bool:
    """
    Aguarda o ZAP iniciar antes de tentar conectar.
    Retorna True se o ZAP estiver pronto, False se esgotou as tentativas.
    """
    for i in range(tentativas):
        try:
            req.get(zap_url, timeout=3)
            print("ZAP está pronto!")
            return True
        except Exception:
            print(f"Aguardando ZAP iniciar... tentativa {i + 1}/{tentativas}")
            time.sleep(intervalo)
    return False

def rodar_zap(url):
    try:
        url = _normalizar_url(url)

        zap_host = os.environ.get("ZAP_HOST", "127.0.0.1")
        zap_url  = f'http://{zap_host}:8090'

        # Aguarda o ZAP iniciar (essencial no Docker)
        if not _aguardar_zap(zap_url):
            print("ZAP não respondeu após todas as tentativas.")
            return "ERRO_PROXY_ZAP"

        zap = ZAPv2(apikey='', proxies={'http': zap_url, 'https': zap_url})

        print(f"Conectado ao ZAP. Versão: {zap.core.version}")

        zap.core.access_url(url)
        time.sleep(2)

        # ── Spider tradicional ────────────────────────────────────────────
        print("Iniciando Spider...")
        scan_id = zap.spider.scan(url)
        while int(zap.spider.status(scan_id)) < 100:
            print(f"Progresso do Spider: {zap.spider.status(scan_id)}%")
            time.sleep(2)
        print("Spider tradicional concluído.")

        # ── Ajax Spider ───────────────────────────────────────────────────
        print("Iniciando Ajax Spider para renderizar JavaScript...")
        zap.ajaxSpider.set_option_max_duration(5)
        zap.ajaxSpider.scan(url)
        while zap.ajaxSpider.status == 'running':
            print("Ajax Spider ainda está explorando a aplicação...")
            time.sleep(5)
        print("Ajax Spider concluído.")

        # ── Active Scan ───────────────────────────────────────────────────
        print(f"Iniciando Active Scan em: {url}")
        zap.ascan.set_option_thread_per_host(15)
        ascan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(ascan_id)) < 100:
            print(f"Progresso do Active Scan: {zap.ascan.status(ascan_id)}%")
            time.sleep(5)

        print("Análise completa. Coletando e agrupando alertas...")
        alertas = zap.core.alerts(baseurl=url)

        if not alertas:
            return "[]"

        alertas_agrupados = _agrupar_alertas(alertas)
        return json.dumps(alertas_agrupados, indent=2, ensure_ascii=False)

    except Exception as erro:
        print(f"Erro detalhado: {erro}")
        return "ERRO_PROXY_ZAP"