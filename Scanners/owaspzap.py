from zapv2 import ZAPv2

def rodar_zap(url):

    try:

        zap = ZAPv2(
            proxies={
                'http': 'http://127.0.0.1:8080',
                'https': 'http://127.0.0.1:8080'
            }
        )

        zap.core.version


        zap.urlopen(url)


        alertas = zap.core.alerts()

        return alertas

    except Exception:

        return "ERRO_PROXY_ZAP"