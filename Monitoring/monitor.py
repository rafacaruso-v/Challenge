import requests as req
import sqlite3
import time
import os
from datetime import datetime
from Database.db import salvar_alerta, listar_ativos_db, atualizar_ativo, registrar_historico_ativo
from MachineLearning.anomaly_detector import verificar_anomalia_ml

LIMIAR_ANOMALIA = 20


def verificar_disponibilidade(usuario_id, ativo_nome, url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resposta = req.get(url, timeout=10, headers=headers)
        if resposta.status_code >= 400:
            salvar_alerta(
                usuario_id=usuario_id,
                ativo_nome=ativo_nome,
                tipo="offline",
                mensagem=f"⚠️ '{ativo_nome}' retornou status {resposta.status_code} às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )
            return False
        return True
    except req.exceptions.ConnectionError:
        salvar_alerta(
            usuario_id=usuario_id,
            ativo_nome=ativo_nome,
            tipo="offline",
            mensagem=f"🔴 '{ativo_nome}' está inacessível (connection error) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        )
        return False
    except req.exceptions.Timeout:
        salvar_alerta(
            usuario_id=usuario_id,
            ativo_nome=ativo_nome,
            tipo="offline",
            mensagem=f"🔴 '{ativo_nome}' não respondeu no tempo limite às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        )
        return False
    except Exception:
        return True


def verificar_anomalia(usuario_id, ativo_id, ativo_nome, score_atual):
    try:
        e_anomalia, detalhe, metodo = verificar_anomalia_ml(usuario_id, ativo_id, ativo_nome, score_atual)

        if e_anomalia:
            prefixo = "🧠" if metodo == "machine_learning" else "🟠"
            salvar_alerta(
                usuario_id=usuario_id,
                ativo_nome=ativo_nome,
                tipo="anomalia",
                mensagem=f"{prefixo} '{ativo_nome}': {detalhe} às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )

    except Exception as e:
        print(f"Erro ao verificar anomalia: {e}")

def _aguardar_zap(zap_url: str, tentativas: int = 10, intervalo: int = 5) -> bool:
    for i in range(tentativas):
        try:
            req.get(zap_url, timeout=3)
            print("ZAP está pronto!")
            return True
        except Exception:
            print(f"Aguardando ZAP iniciar... tentativa {i + 1}/{tentativas}")
            time.sleep(intervalo)
    return False


def _listar_todos_usuario_ids():
    conexao = sqlite3.connect("aspm.db", check_same_thread=False)
    cursor = conexao.cursor()
    cursor.execute("SELECT id FROM usuarios")
    return [row[0] for row in cursor.fetchall()]


def _rescan_usuario(usuario_id):
    from Scanners.owaspzap import rodar_zap
    from Scanners.semgrep import rodar_semgrep
    from Scanners.trivy import rodar_trivy
    from LLMs.gemini import analisar_vulnerabilidades

    ativos = listar_ativos_db(usuario_id)

    if not ativos:
        return

    for ativo in ativos:
        (id_, ativo_usuario_id, nome, tipo, url, ambiente,
         criticidade, score_anterior, analise, ultima_analise) = ativo

        print(f"Re-scan iniciado: {nome} (usuário {usuario_id})")

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

            if crit == "Erro":
                print(f"Análise falhou para {nome}, mantendo dados anteriores.")
                continue

            atualizar_ativo(usuario_id, nome, url, crit, score_novo, analise_nova)

            verificar_anomalia(usuario_id, id_, nome, score_novo)

            registrar_historico_ativo(usuario_id, id_, nome, score_novo)

            if e_url:
                verificar_disponibilidade(usuario_id, nome, url)

            salvar_alerta(
                usuario_id=usuario_id,
                ativo_nome=nome,
                tipo="rescan",
                mensagem=f"✅ Re-scan automático concluído para '{nome}' — Score: {score_novo} ({crit}) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )

            print(f"Re-scan concluído: {nome} — Score: {score_novo}")

        except Exception as e:
            print(f"Erro no re-scan de {nome} (usuário {usuario_id}): {e}")


def rescan_automatico(usuario_id=None):
    from Database.db import registrar_historico

    if usuario_id is not None:
        _rescan_usuario(usuario_id)
        registrar_historico(usuario_id)
        print(f"Histórico atualizado para usuário {usuario_id}.")
        return

    usuario_ids = _listar_todos_usuario_ids()

    if not usuario_ids:
        print("Nenhum usuário cadastrado para re-scan.")
        return

    for uid in usuario_ids:
        _rescan_usuario(uid)
        registrar_historico(uid)

    print(f"Histórico atualizado para {len(usuario_ids)} usuário(s).")