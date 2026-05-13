import time
from zapv2 import ZAPv2

def rodar_zap(url):
    try:
        zap = ZAPv2(
            apikey='2sr513moeq15252q90jocg8s8l',
            proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'}
        )

        print(f"ZAP conectado: {zap.core.version}")
        
        
        print(f"Iniciando Spider na URL: {url}")
        scan_id = zap.spider.scan(url)
        
        timeout = time.time() + 60 * 5 
        
        while int(zap.spider.status(scan_id)) < 100:
            if time.time() > timeout:
                print("Spider atingiu o tempo limite!")
                zap.spider.stop(scan_id)
                break
            time.sleep(2)
            print(f"Progresso do Spider: {zap.spider.status(scan_id)}%")
            
        print("Spider concluído. Coletando alertas...")
        
        alertas = zap.core.alerts(baseurl=url, count=20) 
        
        return alertas

    except Exception as erro:
        print(f"Erro detalhado no ZAP: {erro}")
        return "ERRO_PROXY_ZAP"
