import streamlit as st

from Scanners.semgrep import rodar_semgrep
from IAs.risk_score import calcular_criticidade

from Inventario.asset_manager import (
    adicionar_ativo,
    listar_ativos
)

# =====================================
# CONFIGURAÇÃO
# =====================================

st.set_page_config(
    page_title="ASPM Platform",
    page_icon="🔐",
    layout="wide"
)

st.markdown("🔐 ASPM Platform")

st.write(
    "Application Security Posture Management"
)

# =====================================
# FORMULÁRIO
# =====================================

st.markdown("Cadastrar Ativo")

nome = st.text_input(
    "Nome do ativo"
)

tipo = st.selectbox(
    "Tipo",
    [
        "API",
        "Aplicação Web",
        "Repositório"
    ]
)

url = st.text_input(
    "URL / Caminho"
)

ambiente = st.selectbox(
    "Ambiente",
    [
        "Produção",
        "Homologação",
        "Desenvolvimento"
    ]
)

# =====================================
# BOTÃO DE ANÁLISE
# =====================================

if st.button("Analisar Ativo"):

    with st.spinner("🔄 Analisando ativo..."):

        resultado_scanner = ""

        # Executa scanner apenas em repositórios

        if tipo == "Repositório":

            resultado_scanner = rodar_semgrep(
                url
            )

        # =================================
        # IA CALCULA A CRITICIDADE
        # =================================

        criticidade, score = calcular_criticidade(
            tipo,
            ambiente,
            resultado_scanner
        )

        ativo = {

            "nome": nome,
            "tipo": tipo,
            "url": url,
            "ambiente": ambiente,
            "criticidade": criticidade,
            "score": score
        }

        adicionar_ativo(ativo)

    st.success("✅ Análise concluída!")

    # =====================================
    # RESULTADO
    # =====================================

    st.subheader("Resultado")

    st.write(f"Ativo: {nome}")

    st.metric(
        "Criticidade",
        criticidade
    )

    st.metric(
        "Risk Score",
        score
    )

    # =====================================
    # RESULTADO DO SCANNER
    # =====================================

    if resultado_scanner:

        st.subheader(
            "Resultado do Scanner"
        )

        st.code(resultado_scanner)

# =====================================
# DASHBOARD / INVENTÁRIO
# =====================================

st.markdown("📊 Inventário")

ativos = listar_ativos()

if ativos:

    for ativo in ativos:

        with st.expander(
            f"🔎 {ativo['nome']}"
        ):

            st.write(
                f"Tipo: {ativo['tipo']}"
            )

            st.write(
                f"Ambiente: {ativo['ambiente']}"
            )

            st.write(
                f"Criticidade: {ativo['criticidade']}"
            )

            st.write(
                f"Risk Score: {ativo['score']}"
            )

            if ativo["criticidade"] == "Crítica":
                st.error("⚠️ Risco Crítico")

            elif ativo["criticidade"] == "Alta":
                st.warning("⚠️ Alto Risco")

            else:
                st.success("✔ Risco Controlado")

else:

    st.info(
        "Nenhum ativo analisado."
    )