import requests
import sqlite3
from datetime import datetime
from Database.db import salvar_alerta, listar_ativos_db, atualizar_ativo

LIMIAR_ANOMALIA = 20 

# =====================================
# MONITORAMENTO DE DISPONIBILIDADE
# =====================================
def verificar_disponibilidade(ativo_nome, url):
    try:
        resposta = requests.get(url, timeout=10)
        if resposta.status_code >= 400:
            salvar_alerta(
                ativo_nome=ativo_nome,
                tipo="offline",
                mensagem=f"⚠️ '{ativo_nome}' retornou status {resposta.status_code} às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )
            return False
        return True
    except requests.exceptions.ConnectionError:
        salvar_alerta(
            ativo_nome=ativo_nome,
            tipo="offline",
            mensagem=f"🔴 '{ativo_nome}' está inacessível (connection error) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        )
        return False
    except requests.exceptions.Timeout:
        salvar_alerta(
            ativo_nome=ativo_nome,
            tipo="offline",
            mensagem=f"🔴 '{ativo_nome}' não respondeu no tempo limite às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        )
        return False
    except Exception:
        return True 

# =====================================
# DETECÇÃO DE ANOMALIAS
# =====================================
def verificar_anomalia(ativo_nome, score_atual):
    try:
        conexao = sqlite3.connect("aspm.db", check_same_thread=False)
        cursor = conexao.cursor()

        cursor.execute(
            """
            SELECT score FROM ativos
            WHERE nome = ?
            ORDER BY id DESC
            LIMIT 2
            """,
            (ativo_nome,)
        )
        resultados = cursor.fetchall()

        if len(resultados) < 2:
            return

        score_anterior = resultados[1][0]
        diferenca = score_atual - score_anterior

        if diferenca >= LIMIAR_ANOMALIA:
            salvar_alerta(
                ativo_nome=ativo_nome,
                tipo="anomalia",
                mensagem=f"🟠 '{ativo_nome}' teve aumento brusco de score: {score_anterior} → {score_atual} (+{diferenca} pontos) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )

    except Exception as e:
        print(f"Erro ao verificar anomalia: {e}")

# =====================================
# RE-SCAN AUTOMÁTICO
# =====================================
def rescan_automatico():
    from Scanners.owaspzap import rodar_zap
    from Scanners.semgrep import rodar_semgrep
    from Scanners.trivy import rodar_trivy
    from IAs.gemini import analisar_vulnerabilidades
    from Database.db import atualizar_ativo

    ativos = listar_ativos_db()

    if not ativos:
        print("Nenhum ativo cadastrado para re-scan.")
        return

    for ativo in ativos:
        id_, nome, tipo, url, ambiente, criticidade, score_anterior, analise, ultima_analise = ativo

        print(f"Re-scan iniciado: {nome}")

        try:
            e_url = url.startswith("http://") or url.startswith("https://")

            res_sast = rodar_semgrep(url) if tipo == "Repositório" else ""
            res_sca  = rodar_trivy(url)   if tipo == "Repositório" else ""
            res_dast = rodar_zap(url)     if tipo in ["API", "Aplicação"] else ""

            if res_dast == "ERRO_PROXY_ZAP":
                print(f"ZAP indisponível para {nome}, pulando DAST.")
                res_dast = ""

            crit, score_novo, analise_nova = analisar_vulnerabilidades(
                tipo, url, ambiente, res_sast, res_dast, res_sca
            )

            atualizar_ativo(nome, url, crit, score_novo, analise_nova)

            verificar_anomalia(nome, score_novo)

            if e_url:
                verificar_disponibilidade(nome, url)

            salvar_alerta(
                ativo_nome=nome,
                tipo="rescan",
                mensagem=f"✅ Re-scan automático concluído para '{nome}' — Score: {score_novo} ({crit}) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )

            print(f"Re-scan concluído: {nome} — Score: {score_novo}")

        except Exception as e:
            print(f"Erro no re-scan de {nome}: {e}")