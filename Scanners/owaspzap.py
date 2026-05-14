import time
import os
from zapv2 import ZAPv2

def rodar_zap(url):
    try:
        zap_url = 'http://host.docker.internal:8090'
        
        zap = ZAPv2(
            apikey='', 
            proxies={'http': zap_url, 'https': zap_url}
        )

        # Validação simples de conexão
        print(f"Conectado ao ZAP Desktop. Versão: {zap.core.version}")
        
        # O ZAP precisa acessar a URL uma vez para reconhecê-la
        zap.core.access_url(url)
        time.sleep(2)

        print(f"Iniciando Spider na URL: {url}")
        scan_id = zap.spider.scan(url)
        
        # Tempo limite de 5 minutos
        timeout = time.time() + 60 * 5 
        
        while True:
            status = int(zap.spider.status(scan_id))
            print(f"Progresso do Spider: {status}%")
            
            if status >= 100:
                break
                
            if time.time() > timeout:
                print("Spider atingiu o tempo limite!")
                zap.spider.stop(scan_id)
                break
                
            time.sleep(2)
            
        print("Spider concluído. Coletando alertas encontrados...")
        
        # Coleta os alertas (vulnerabilidades) encontrados
        alertas = zap.core.alerts(baseurl=url, count=50)
        
        # Se não achar nada na URL específica, traz os alertas gerais
        if not alertas:
            alertas = zap.core.alerts(count=20)
            
        return alertas

    except Exception as erro:
        print(f"Erro detalhado de conexão: {erro}")
        return "ERRO_PROXY_ZAP"
