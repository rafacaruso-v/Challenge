from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional

from Database.db import (
    criar_tabela, validar_api_key, buscar_ativo_por_nome, criar_ativo,
    adicionar_componente, atualizar_componente, buscar_componente_por_tipo,
    registrar_historico_componente,
)
from MachineLearning.risk_score_model import calcular_score_ml, criticidade_por_score

app = FastAPI(title="ASPM Webhook API")


@app.on_event("startup")
def inicializar_banco():
    criar_tabela()


class AchadoSemgrep(BaseModel):
    check_id: str = "?"
    path: str = "?"
    linha: str = "?"
    severidade: str = "INFO"
    mensagem: str = ""


class AchadoTrivy(BaseModel):
    severidade: str = "UNKNOWN"
    titulo: str = "?"
    descricao: str = ""


class AchadoCheckov(BaseModel):
    check_id: str = "?"
    check_name: str = "?"
    recurso: str = "?"
    arquivo: str = "?"


class AchadoGitleaks(BaseModel):
    regra: str = "?"
    arquivo: str = "?"
    linha: str = "?"
    descricao: str = ""
    segredo_mascarado: str = "***"


class AchadoDLP(BaseModel):
    tipo: str = "?"
    arquivo: str = "?"
    linha: str = "?"
    valor_mascarado: str = "***"
    confianca: str = "media"


class PayloadPrScan(BaseModel):
    repositorio: str
    ambiente: Optional[str] = "Produção"
    pr_url: Optional[str] = None
    resumo_ia: Optional[str] = ""
    achados_semgrep: list[AchadoSemgrep] = []
    achados_trivy: list[AchadoTrivy] = []
    achados_checkov: list[AchadoCheckov] = []
    achados_gitleaks: list[AchadoGitleaks] = []
    achados_dlp: list[AchadoDLP] = []


_MAPA_SEMGREP = {"ERROR": "critico", "WARNING": "medio", "INFO": "baixo"}
_MAPA_TRIVY = {"CRITICAL": "critico", "HIGH": "alto", "MEDIUM": "medio", "LOW": "baixo"}
_EMOJI_NIVEL = {"critico": ("🔴", "Crítico"), "alto": ("🟠", "Alto"), "medio": ("🟡", "Médio"), "baixo": ("🟢", "Baixo")}
_SEVERIDADE_PADRAO_SECRETS = "alto"
_MAPA_DLP_CONFIANCA = {"alta": "alto", "media": "medio"}


def _bucketizar_sast(achados: list) -> dict:
    baldes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    for a in achados:
        nivel = _MAPA_SEMGREP.get(a.severidade.upper(), "baixo")
        texto = f"{a.check_id}: {a.mensagem or 'Achado do Semgrep'} — {a.path}:{a.linha}"
        baldes[nivel].append(texto)
    return baldes


def _bucketizar_sca(achados: list) -> dict:
    baldes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    for a in achados:
        nivel = _MAPA_TRIVY.get(a.severidade.upper(), "medio")
        texto = f"{a.titulo}: {a.descricao}"
        baldes[nivel].append(texto)
    return baldes


def _bucketizar_iac(achados: list) -> dict:
    baldes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    for a in achados:
        texto = f"{a.recurso}: {a.check_name} ({a.check_id}) em {a.arquivo}"
        baldes["medio"].append(texto)
    return baldes


def _bucketizar_secrets(achados: list) -> dict:
    baldes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    for a in achados:
        texto = f"Credencial do tipo '{a.regra}' detectada em {a.arquivo}:{a.linha}."
        baldes[_SEVERIDADE_PADRAO_SECRETS].append(texto)
    return baldes


def _bucketizar_dlp(achados: list) -> dict:
    baldes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    for a in achados:
        nivel = _MAPA_DLP_CONFIANCA.get(a.confianca, "medio")
        texto = f"Dado do tipo '{a.tipo}' encontrado em {a.arquivo}:{a.linha} (confiança: {a.confianca})."
        baldes[nivel].append(texto)
    return baldes


def _montar_bloco(baldes: dict) -> str:
    bloco = ""
    for nivel in ("critico", "alto", "medio", "baixo"):
        itens = baldes.get(nivel, [])
        if itens:
            emoji, label = _EMOJI_NIVEL[nivel]
            bloco += f"[NIVEL:{nivel}]{emoji} {label}[/NIVEL]\n"
            for item in itens:
                bloco += f"- {item}\n"
            bloco += "\n"
    return bloco


def _contar(baldes: dict) -> dict:
    return {nivel: len(itens) for nivel, itens in baldes.items()}


@app.post("/webhook/pr-scan")
def receber_scan_pr(payload: PayloadPrScan, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Cabeçalho Authorization ausente ou inválido.")

    api_key = authorization.removeprefix("Bearer ").strip()
    usuario_id = validar_api_key(api_key)
    if usuario_id is None:
        raise HTTPException(status_code=401, detail="API Key inválida.")

    ativo_id = buscar_ativo_por_nome(usuario_id, payload.repositorio)
    ativo_criado_agora = False
    if ativo_id is None:
        ativo_id = criar_ativo(
            usuario_id, payload.repositorio,
            descricao="Ativo criado automaticamente a partir da integração CI/CD (Pull Request)."
        )
        ativo_criado_agora = True

    baldes_sast = _bucketizar_sast(payload.achados_semgrep)
    baldes_sca = _bucketizar_sca(payload.achados_trivy)
    baldes_iac = _bucketizar_iac(payload.achados_checkov)
    baldes_secrets = _bucketizar_secrets(payload.achados_gitleaks)
    baldes_dlp = _bucketizar_dlp(payload.achados_dlp)

    bloco_sast = _montar_bloco(baldes_sast) or "✅ Nenhuma vulnerabilidade encontrada pelo SAST.\n"
    bloco_dast = "✅ Nenhuma vulnerabilidade encontrada pelo DAST.\n"
    bloco_sca = _montar_bloco(baldes_sca) or "✅ Nenhuma vulnerabilidade de dependências encontrada.\n"
    bloco_cspm = "✅ Nenhum achado de postura de nuvem encontrado.\n"
    bloco_iac = _montar_bloco(baldes_iac) or "✅ Nenhum achado de infraestrutura como código encontrado.\n"
    bloco_secrets = _montar_bloco(baldes_secrets) or "✅ Nenhuma credencial exposta encontrada.\n"
    bloco_dlp = _montar_bloco(baldes_dlp) or "✅ Nenhum dado sensível de terceiros encontrado.\n"
    bloco_fp = "✅ Nenhum achado foi identificado como falso positivo nesta análise.\n"

    texto_formatado = f"""---VULNS_SAST_DAST---
{bloco_sast.strip()}
---DIVISOR---
{bloco_dast.strip()}
---VULNS_SCA---
{bloco_sca.strip()}
---VULNS_CSPM---
{bloco_cspm.strip()}
---VULNS_IAC---
{bloco_iac.strip()}
---VULNS_SECRETS---
{bloco_secrets.strip()}
---VULNS_DLP---
{bloco_dlp.strip()}
---VULNS_FP---
{bloco_fp.strip()}
---RELATORIO---
### Análise de Postura de Segurança
{payload.resumo_ia or 'Scan automático disparado via Pull Request.'}

### Plano de Ação Recomendado
Revise os achados listados nas abas de detalhamento técnico acima. Este componente foi gerado automaticamente a partir de um Pull Request{f' ({payload.pr_url})' if payload.pr_url else ''}.
"""

    todos_baldes = (baldes_sast, baldes_sca, baldes_iac, baldes_secrets, baldes_dlp)
    n_critico = sum(_contar(b)["critico"] for b in todos_baldes)
    n_alto = sum(_contar(b)["alto"] for b in todos_baldes)
    n_medio = sum(_contar(b)["medio"] for b in todos_baldes)
    n_baixo = sum(_contar(b)["baixo"] for b in todos_baldes)

    score = calcular_score_ml(n_critico, n_alto, n_medio, n_baixo, payload.ambiente)
    criticidade = criticidade_por_score(score)

    componente_id = buscar_componente_por_tipo(usuario_id, ativo_id, tipo="Repositório")
    componente_criado_agora = False

    if componente_id:
        atualizar_componente(
            usuario_id, componente_id,
            criticidade=criticidade, score=score, analise=texto_formatado,
            url=payload.pr_url,
        )
    else:
        componente_id = adicionar_componente(
            usuario_id, ativo_id, tipo="Repositório", ambiente=payload.ambiente,
            url=payload.pr_url, criticidade=criticidade, score=score, analise=texto_formatado,
        )
        componente_criado_agora = True

    registrar_historico_componente(usuario_id, componente_id, ativo_id, score)

    return {
        "sucesso": True,
        "ativo_id": ativo_id,
        "ativo_criado_agora": ativo_criado_agora,
        "componente_id": componente_id,
        "componente_criado_agora": componente_criado_agora,
        "criticidade": criticidade,
        "score": score,
    }


@app.get("/health")
def health():
    return {"status": "ok"}