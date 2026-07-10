import time
import json
import os
import requests as req
from zapv2 import ZAPv2

CAMINHOS_OPENAPI_COMUNS = [
    "/openapi.json",              
    "/swagger.json",              
    "/swagger/v1/swagger.json",   
    "/v3/api-docs",               
    "/v2/api-docs",               
    "/api-json",                  
    "/api-docs",                            
    "/api/schema/",                
    "/api/schema.json",           
    "/api/documentation",         
    "/docs/api-docs.json",        
    "/apispec.json",                       
    "/swagger/doc.json",          
    "/openapi.yaml",
    "/swagger.yaml",
    "/v2/swagger.json"
]


def _normalizar_url(url: str) -> str:
    return url.replace("localhost", "127.0.0.1")


def _parece_especificacao_valida(conteudo: str) -> bool:
    trecho = conteudo[:500].lower()
    return ('"openapi"' in trecho) or ('"swagger"' in trecho) or ("openapi:" in trecho) or ("swagger:" in trecho)


def detectar_openapi(url: str, timeout: int = 5) -> str:
    base = url.rstrip("/")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    for caminho in CAMINHOS_OPENAPI_COMUNS:
        candidato = base + caminho
        try:
            resposta = req.get(candidato, timeout=timeout, headers=headers)
            if resposta.status_code == 200 and _parece_especificacao_valida(resposta.text):
                print(f"Especificação OpenAPI/Swagger encontrada em: {candidato}")
                return candidato
        except Exception:
            continue

    return None


def _agrupar_alertas(alertas: list) -> list:
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


def _aguardar_zap(zap_url: str, tentativas: int = 7, intervalo: int = 3) -> bool:
    for i in range(tentativas):
        try:
            req.get(zap_url, timeout=3)
            print("ZAP está pronto!")
            return True
        except Exception:
            print(f"Aguardando ZAP iniciar... tentativa {i + 1}/{tentativas}")
            time.sleep(intervalo)
    return False


def _conectar_zap():
    zap_host = os.environ.get("ZAP_HOST", "127.0.0.1")
    zap_url  = f'http://{zap_host}:8090'

    if not _aguardar_zap(zap_url):
        return None

    zap = ZAPv2(apikey='', proxies={'http': zap_url, 'https': zap_url})
    print(f"Conectado ao ZAP. Versão: {zap.core.version}")
    return zap


def _rodar_active_scan(zap, url):
    print(f"Iniciando Active Scan em: {url}")
    zap.ascan.set_option_thread_per_host(15)
    ascan_id = zap.ascan.scan(url)
    while int(zap.ascan.status(ascan_id)) < 100:
        print(f"Progresso do Active Scan: {zap.ascan.status(ascan_id)}%")
        time.sleep(5)


def _rodar_analise_aplicacao(zap, url):
    zap.core.access_url(url)
    time.sleep(2)

    print("Iniciando Spider...")
    scan_id = zap.spider.scan(url)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Progresso do Spider: {zap.spider.status(scan_id)}%")
        time.sleep(2)
    print("Spider tradicional concluído.")

    print("Iniciando Ajax Spider para renderizar JavaScript...")
    zap.ajaxSpider.set_option_max_duration(5)
    zap.ajaxSpider.scan(url)
    while zap.ajaxSpider.status == 'running':
        print("Ajax Spider ainda está explorando a aplicação...")
        time.sleep(5)
    print("Ajax Spider concluído.")

    _rodar_active_scan(zap, url)


def _rodar_analise_api(zap, url, openapi_url):
    print(f"Importando especificação OpenAPI/Swagger: {openapi_url}")
    try:
        resultado_import = zap.openapi.import_url(openapi_url, hostoverride=url)
        print(f"Endpoints importados: {resultado_import}")
    except Exception as erro_import:
        print(f"Falha ao importar especificação OpenAPI: {erro_import}")
        return "ERRO_IMPORT_OPENAPI"

    time.sleep(2)
    _rodar_active_scan(zap, url)
    return None


def rodar_zap(url, tipo=None):
    try:
        url = _normalizar_url(url)

        if tipo == "API":
            openapi_url = detectar_openapi(url)
            if openapi_url is None:
                print("Nenhuma especificação OpenAPI/Swagger encontrada nos caminhos comuns.")
                return "ERRO_OPENAPI_NAO_ENCONTRADO"

        zap = _conectar_zap()
        if zap is None:
            print("ZAP não respondeu após todas as tentativas.")
            return "ERRO_PROXY_ZAP"

        if tipo == "API":
            erro = _rodar_analise_api(zap, url, openapi_url)
            if erro:
                return erro
        else:
            _rodar_analise_aplicacao(zap, url)

        print("Análise completa. Coletando e agrupando alertas...")
        alertas = zap.core.alerts(baseurl=url)

        if not alertas:
            return "[]"

        alertas_agrupados = _agrupar_alertas(alertas)
        return json.dumps(alertas_agrupados, indent=2, ensure_ascii=False)

    except Exception as erro:
        print(f"Erro detalhado: {erro}")
        return "ERRO_PROXY_ZAP"