import time
from zapv2 import ZAPv2

def rodar_zap(url):
    try:
        zap = ZAPv2(
            apikey='2sr513moeq15252q90jocg8s8l',
            proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
        )

        print(f"ZAP conectado: {zap.core.version}")
        
        
        print(f"Iniciando Spider na URL: {url}")
        scan_id = zap.spider.scan(url)
        
        
        while int(zap.spider.status(scan_id)) < 100:
            time.sleep(2)
            
        print("Spider concluído. Coletando alertas...")
        alertas = zap.core.alerts()
        return alertas

    except Exception as erro:
        print(f"Erro ZAP: {erro}")
        return "ERRO_PROXY_ZAP"
