from Database.db import (
    listar_ativos_db,
    listar_alertas_ativos,
    buscar_usuario_por_id,
)

try:
    from Monitoring.threat_intelligence import buscar_cves_recentes
except ImportError:
    buscar_cves_recentes = None


CONTEXTO_IDENTIDADE = """
Você é o Assistente de IA da ASPM Platform, uma plataforma de Application
Security Posture Management (ASPM). Você está embarcado dentro da própria
aplicação (uma interface web feita em Streamlit), disponível para o usuário
logado consultar dados de segurança em linguagem natural.

Sua função é ajudar o usuário a entender a postura de segurança dos Ativos
cadastrados (repositórios, APIs, aplicações e contas cloud AWS), interpretar
vulnerabilidades encontradas pelos scanners (Semgrep, Trivy, Checkov, OWASP
ZAP, CSPM), explicar alertas de monitoramento e produzir resumos executivos —
sempre com base nos dados reais fornecidos abaixo, nunca inventando
informação que não esteja neles.
"""


def _obter_nome_usuario(usuario_id) -> str:
    """Busca o nome de exibição do usuário logado para dar contexto ao prompt.
    Cai para algo genérico se não encontrar (não deve travar a conversa)."""
    try:
        usuario = buscar_usuario_por_id(usuario_id)
    except Exception:
        usuario = None

    if not usuario:
        return "Usuário"

    # buscar_usuario_por_id retorna: id, username, email, senha_hash, nome, role
    nome = usuario[4] or usuario[1]
    return nome or "Usuário"


def _e_pergunta_de_identidade(pergunta_lower: str) -> bool:
    gatilhos = (
        "quem é você", "quem é vc", "quem és", "quem e voce", "quem e vc",
        "o que você é", "o que vc é", "o que voce e",
        "qual seu nome", "qual é seu nome", "seu nome",
        "o que você faz", "o que vc faz", "sua função", "suas funções",
        "quem te criou", "quem criou você", "você é um bot", "você é uma ia",
        "voce e um bot", "voce e uma ia", "onde você está", "onde vc esta",
    )
    return any(gatilho in pergunta_lower for gatilho in gatilhos)


def preparar_prompt(usuario_id, pergunta):

    pergunta_lower = pergunta.lower()
    nome_usuario = _obter_nome_usuario(usuario_id)

    if _e_pergunta_de_identidade(pergunta_lower):
        return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}, o usuário atualmente logado na
plataforma.

O usuário perguntou sobre você:

{pergunta}

Responda de forma direta e amigável, explicando quem você é, onde está
rodando (dentro da ASPM Platform) e qual sua função, usando como base as
informações de contexto acima. Não invente capacidades ou integrações que
não foram descritas nesse contexto.
"""

    if (
        "ativo" in pergunta_lower
        or "score" in pergunta_lower
        or "vulnerabilidade" in pergunta_lower
        or "criticidade" in pergunta_lower
    ):

        ativos = listar_ativos_db(usuario_id)

        return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}.

O usuário perguntou:

{pergunta}

Esses são os ativos cadastrados:

{ativos}

Responda apenas utilizando essas informações.

Caso não exista informação suficiente, diga isso claramente.
"""
    if (
        "alerta" in pergunta_lower
        or "anomalia" in pergunta_lower
        or "offline" in pergunta_lower
    ):

        alertas = listar_alertas_ativos(usuario_id)

        return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}.

Pergunta:

{pergunta}

Alertas encontrados:

{alertas}

Faça um resumo explicando:

- quais ativos possuem alertas;
- quais riscos existem;
- quais ações devem ser tomadas;
- quais alertas possuem maior prioridade.
"""
    if (
        "cve" in pergunta_lower
        or "ameaça" in pergunta_lower
        or "threat" in pergunta_lower
        or "intelligence" in pergunta_lower
    ):

        if buscar_cves_recentes is None:
            return """
O módulo Threat Intelligence ainda não está instalado.
"""

        cves = buscar_cves_recentes()

        if isinstance(cves, str):
            return cves

        cves_criticas = [
            c
            for c in cves
            if c["severidade"] == "CRITICAL"
        ]

        if not cves_criticas:
            cves_criticas = cves

        return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}.

O usuário perguntou:

{pergunta}

Estas são as CVEs recentes:

{cves_criticas}

Para cada CVE explique:

• O impacto da vulnerabilidade;

• Os produtos afetados;

• A criticidade (CVSS);

• A prioridade de correção;

• As recomendações de mitigação.

Ao final faça um resumo executivo indicando quais vulnerabilidades devem ser tratadas primeiro.
"""
    if (
        "relatório" in pergunta_lower
        or "resumo" in pergunta_lower
        or "dashboard" in pergunta_lower
    ):

        ativos = listar_ativos_db(usuario_id)
        alertas = listar_alertas_ativos(usuario_id)

        return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}.

Crie um relatório executivo utilizando os dados abaixo.

Ativos:

{ativos}

Alertas:

{alertas}

O relatório deve conter:

1. Resumo Executivo;

2. Quantidade de ativos;

3. Principais riscos encontrados;

4. Vulnerabilidades críticas;

5. Recomendações de segurança;

6. Prioridades de correção.

Escreva de forma profissional e organizada.
"""
    return f"""
{CONTEXTO_IDENTIDADE}

Você está conversando com {nome_usuario}.

Pergunta do usuário:

{pergunta}
"""