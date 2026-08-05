import requests as req
import sqlite3
import time
from datetime import datetime
from Database.db import (
    salvar_alerta,
    listar_ativos_db,
    listar_componentes,
    atualizar_componente,
    registrar_historico_componente,
)
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


def verificar_anomalia(usuario_id, componente_id, identificador_exibicao, score_atual):
    """
    NOTA: 'componente_id' é passado no lugar de 'ativo_id' que a função
    recebia antes. Isso é intencional — o histórico de score agora é
    rastreado por componente (um ativo pode ter vários componentes, cada
    um com sua própria série temporal de score). Se
    MachineLearning/anomaly_detector.py consulta uma tabela/coluna
    'ativo_id' internamente (ex: historico_ativos, que não existe mais),
    esse arquivo também precisa ser adaptado para usar historico_componentes
    e a função listar_historico_componente(usuario_id, componente_id).
    """
    try:
        e_anomalia, detalhe, metodo = verificar_anomalia_ml(usuario_id, componente_id, identificador_exibicao, score_atual)

        if e_anomalia:
            prefixo = "🧠" if metodo == "machine_learning" else "🟠"
            salvar_alerta(
                usuario_id=usuario_id,
                ativo_nome=identificador_exibicao,
                tipo="anomalia",
                mensagem=f"{prefixo} '{identificador_exibicao}': {detalhe} às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
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


def _rescan_componente(usuario_id, ativo_id, ativo_nome, componente):
    """
    Re-executa o scan apropriado para um único componente, de acordo com
    seu tipo (Repositório / API / Aplicação / Conta Cloud (AWS)).

    Tupla 'componente' vem de listar_componentes(), nesta ordem:
    0 id, 1 ativo_id, 2 usuario_id, 3 tipo, 4 ambiente, 5 url,
    6 aws_role_arn, 7 aws_region, 8 criticidade, 9 score, 10 analise,
    11 ultima_analise, 12 criado_em
    """
    from Scanners.owaspzap import rodar_zap
    from Scanners.semgrep import rodar_semgrep
    from Scanners.trivy import rodar_trivy
    from Scanners.checkov import rodar_checkov
    from CloudAws.cspm import run_cspm_scan
    from LLMs.gemini import analisar_vulnerabilidades, formatar_achados_cspm, formatar_achados_iac

    (comp_id, _ativo_id, comp_usuario_id, tipo, ambiente, url,
     aws_role_arn, aws_region, _criticidade_anterior, _score_anterior,
     _analise_anterior, _ultima_analise, _criado_em) = componente

    identificador_exibicao = f"{ativo_nome} ({tipo} · {ambiente})"
    print(f"Re-scan iniciado: {identificador_exibicao} (usuário {usuario_id})")

    try:
        if tipo == "Conta Cloud (AWS)":
            if not aws_role_arn:
                print(f"Componente cloud sem ARN configurado, pulando: {identificador_exibicao}")
                return

            achados = run_cspm_scan(aws_role_arn, aws_region or "us-east-1")
            texto_cspm = formatar_achados_cspm(achados)

            crit, score_novo, analise_nova = analisar_vulnerabilidades(
                tipo="Conta Cloud (AWS)",
                url=aws_role_arn,
                ambiente=ambiente,
                resultado_sast="",
                resultado_dast="",
                resultado_sca="",
                resultado_cspm=texto_cspm,
            )

        else:
            from Scanners.repo_utils import preparar_repositorio, limpar_repositorio

            res_sast = res_sca = ""
            res_iac = formatar_achados_iac([])
            res_dast = rodar_zap(url, tipo=tipo) if tipo in ["API", "Aplicação"] else ""

            if tipo == "Repositório":
                try:
                    caminho_local, deve_limpar = preparar_repositorio(url)
                except RuntimeError as e:
                    print(f"Erro ao clonar repositório para re-scan de {identificador_exibicao}: {e}")
                    return
                try:
                    res_sast = rodar_semgrep(caminho_local)
                    res_sca  = rodar_trivy(caminho_local)
                    res_iac_bruto = rodar_checkov(caminho_local)
                    res_iac = formatar_achados_iac(res_iac_bruto)
                finally:
                    if deve_limpar:
                        limpar_repositorio(caminho_local)

            if res_dast == "ERRO_PROXY_ZAP":
                print(f"ZAP indisponível para {identificador_exibicao}, pulando DAST.")
                res_dast = ""

            if res_dast == "ERRO_OPENAPI_NAO_ENCONTRADO":
                print(f"Especificação OpenAPI não encontrada para {identificador_exibicao}, pulando DAST neste re-scan.")
                res_dast = ""

            crit, score_novo, analise_nova = analisar_vulnerabilidades(
                tipo, url, ambiente, res_sast, res_dast, res_sca, resultado_iac=res_iac
            )

        if crit == "Erro":
            print(f"Análise falhou para {identificador_exibicao}, mantendo dados anteriores.")
            return

        atualizar_componente(comp_usuario_id, comp_id, crit, score_novo, analise_nova)

        verificar_anomalia(usuario_id, comp_id, identificador_exibicao, score_novo)

        registrar_historico_componente(usuario_id, comp_id, ativo_id, score_novo)

        if tipo != "Conta Cloud (AWS)" and url and (url.startswith("http://") or url.startswith("https://")):
            verificar_disponibilidade(usuario_id, ativo_nome, url)

        salvar_alerta(
            usuario_id=usuario_id,
            ativo_nome=ativo_nome,
            tipo="rescan",
            mensagem=f"✅ Re-scan automático concluído para '{identificador_exibicao}' — Score: {score_novo} ({crit}) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        )

        print(f"Re-scan concluído: {identificador_exibicao} — Score: {score_novo}")

    except Exception as e:
        print(f"Erro no re-scan de {identificador_exibicao} (usuário {usuario_id}): {e}")


def _rescan_usuario(usuario_id):
    ativos = listar_ativos_db(usuario_id)

    if not ativos:
        return

    for ativo in ativos:
        ativo_id   = ativo[0]
        ativo_nome = ativo[2]

        componentes = listar_componentes(usuario_id, ativo_id)
        if not componentes:
            continue

        for componente in componentes:
            _rescan_componente(usuario_id, ativo_id, ativo_nome, componente)


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