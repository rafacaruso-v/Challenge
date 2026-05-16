import time
from zapv2 import ZAPv2

def rodar_zap(url):
    try:
        zap_url = 'http://127.0.0.1:8090'
        zap = ZAPv2(apikey='', proxies={'http': zap_url, 'https': zap_url})

        print(f"Conectado ao ZAP. Versão: {zap.core.version}")
        
        zap.core.access_url(url)
        time.sleep(2)

        print(f"Iniciando Spider...")
        scan_id = zap.spider.scan(url)
        while int(zap.spider.status(scan_id)) < 100:
            print(f"Progresso do Spider: {zap.spider.status(scan_id)}%")
            time.sleep(2)
        
        print("Análise completa. Coletando resultados do Spider...")
        
  
        print(f"Iniciando Active Scan em: {url}")
        zap.ascan.set_option_thread_per_host(10)
        ascan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(ascan_id)) < 100:
            print(f"Progresso do Active Scan: {zap.ascan.status(ascan_id)}%")
            time.sleep(5)

        print("Análise completa. Coletando alertas...")
        
    
        alertas = zap.core.alerts(baseurl=url)
        
        return alertas

    except Exception as erro:
        print(f"Erro detalhado: {erro}")
        return "ERRO_PROXY_ZAP"
