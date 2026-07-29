from Database.db import (
    listar_ativos_db,
    listar_alertas_ativos,
)

try:
    from Monitoring.threat_intelligence import buscar_cves_recentes
except ImportError:
    buscar_cves_recentes = None


def preparar_prompt(usuario_id, pergunta):

    pergunta_lower = pergunta.lower()

    if (
        "ativo" in pergunta_lower
        or "score" in pergunta_lower
        or "vulnerabilidade" in pergunta_lower
        or "criticidade" in pergunta_lower
    ):

        ativos = listar_ativos_db(usuario_id)

        return f"""
Você é um especialista em ASPM.

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
Você é um especialista em monitoramento.

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
Você é um Analista de Threat Intelligence.

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
Você é um consultor de segurança.

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
    return pergunta