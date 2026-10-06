# ASPM Platform - Application Security Posture Management (ASPM) platform that centralizes asset discovery, security scanning (SAST, DAST, SCA, IaC, CSPM, Secrets, DLP), and security findings, consolidating everything into a single application/business risk dashboard.
#
# Copyright (C) 2026 Guilherme Monteiro, Rafael Caruso, João Pedro
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os
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
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token and "github.com" in url:
            headers["Authorization"] = f"Bearer {token}"

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
    from Scanners.owaspzap import rodar_zap
    from Scanners.semgrep import rodar_semgrep
    from Scanners.trivy import rodar_trivy
    from Scanners.checkov import rodar_checkov
    from CloudAws.cspm import run_cspm_scan
    from LLMs.gemini import analisar_vulnerabilidades, formatar_achados_cspm, formatar_achados_iac
    from MachineLearning.false_positive import reduzir_falsos_positivos_cspm, reduzir_falsos_positivos_iac

    (comp_id, _ativo_id, comp_usuario_id, tipo, ambiente, url,
     aws_role_arn, aws_region, _criticidade_anterior, _score_anterior,
     _analise_anterior, _ultima_analise, _criado_em) = componente

    identificador_exibicao = f"{ativo_nome} ({tipo} · {ambiente})"
    print(f"Re-scan iniciado: {identificador_exibicao} (usuário {usuario_id})")

    try:
        if tipo == "Cloud":
            if not aws_role_arn:
                print(f"Componente cloud sem ARN configurado, pulando: {identificador_exibicao}")
                return None

            achados, _inventario = run_cspm_scan(aws_role_arn, aws_region or "us-east-2")
            achados_filtrados, descartados_cspm = reduzir_falsos_positivos_cspm(achados)
            texto_cspm = formatar_achados_cspm(achados_filtrados)

            crit, score_novo, analise_nova = analisar_vulnerabilidades(
                tipo="Cloud",
                url=aws_role_arn,
                ambiente=ambiente,
                resultado_sast="",
                resultado_dast="",
                resultado_sca="",
                resultado_cspm=texto_cspm,
                descartados_externos=descartados_cspm,
            )

        else:
            from Scanners.repo_utils import preparar_repositorio, preparar_repositorio_upload, limpar_repositorio

            res_sast = res_sca = ""
            res_iac = formatar_achados_iac([])
            descartados_iac = None
            res_dast = rodar_zap(url, tipo=tipo) if tipo in ["API", "Aplicação"] else ""

            if tipo == "Repositório":
                try:
                    if url and url.startswith("db://"):
                        caminho_local, deve_limpar = preparar_repositorio_upload(url)
                    else:
                        caminho_local, deve_limpar = preparar_repositorio(url)
                except RuntimeError as e:
                    print(f"Erro ao preparar repositório para re-scan de {identificador_exibicao}: {e}")
                    return None
                try:
                    res_sast = rodar_semgrep(caminho_local)
                    res_sca  = rodar_trivy(caminho_local)
                    res_iac_bruto = rodar_checkov(caminho_local)
                    res_iac_bruto, descartados_iac = reduzir_falsos_positivos_iac(res_iac_bruto)
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
                tipo, url, ambiente, res_sast, res_dast, res_sca,
                resultado_iac=res_iac, descartados_externos=descartados_iac,
            )

        if crit == "Erro":
            print(f"Análise falhou para {identificador_exibicao}, mantendo dados anteriores.")
            return None

        atualizar_componente(comp_usuario_id, comp_id, crit, score_novo, analise_nova)

        verificar_anomalia(usuario_id, comp_id, identificador_exibicao, score_novo)

        registrar_historico_componente(usuario_id, comp_id, ativo_id, score_novo)

        if tipo != "Cloud" and url and (url.startswith("http://") or url.startswith("https://")):
            verificar_disponibilidade(usuario_id, ativo_nome, url)

        print(f"Re-scan concluído: {identificador_exibicao} — Score: {score_novo}")

        return {"identificador": identificador_exibicao, "score": score_novo, "criticidade": crit}

    except Exception as e:
        print(f"Erro no re-scan de {identificador_exibicao} (usuário {usuario_id}): {e}")
        return None


def _rescan_usuario(usuario_id):
    ativos = listar_ativos_db(usuario_id)

    if not ativos:
        return

    resultados = []

    for ativo in ativos:
        ativo_id   = ativo[0]
        ativo_nome = ativo[2]

        componentes = listar_componentes(usuario_id, ativo_id)
        if not componentes:
            continue

        for componente in componentes:
            resultado = _rescan_componente(usuario_id, ativo_id, ativo_nome, componente)
            if resultado:
                resultados.append(resultado)

    if resultados:
        contagem_por_criticidade = {}
        for r in resultados:
            contagem_por_criticidade[r["criticidade"]] = contagem_por_criticidade.get(r["criticidade"], 0) + 1

        resumo_criticidade = ", ".join(
            f"{qtd} {crit}" for crit, qtd in contagem_por_criticidade.items()
        )

        salvar_alerta(
            usuario_id=usuario_id,
            ativo_nome="*",
            tipo="rescan",
            mensagem=(
                f"✅ Re-scan automático concluído: {len(resultados)} componente(s) atualizado(s) "
                f"({resumo_criticidade}) às {datetime.now().strftime('%d/%m/%Y %H:%M')}"
            )
        )

    try:
        from LLMs.sugestoes import gerar_sugestoes_ia
        gerar_sugestoes_ia(usuario_id)
    except Exception as e:
        print(f"[AVISO] Falha ao gerar sugestões de agrupamento para usuário {usuario_id}: {e}")


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
