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

st.markdown(
    """
    <style>

    /* =========================================
       FUNDO PRINCIPAL
    ========================================= */

    .stApp {

        background:
        radial-gradient(
            circle at top,
            #2b0a3d 0%,
            #1e1b4b 25%,
            #111827 55%,
            #0d1117 100%
        );

        color: white;
    }

    /* =========================================
       SIDEBAR
    ========================================= */

    section[data-testid="stSidebar"] {

        background-color: rgba(13,17,23,0.95);

        border-right:
        1px solid rgba(168,85,247,0.15);

        backdrop-filter: blur(10px);
    }

    /* =========================================
       TÍTULO PRINCIPAL
    ========================================= */

    h1 {

        font-size: 70px;

        font-weight: 800;

        text-align: center;

        background:
        linear-gradient(
            90deg,
            #7c3aed,
            #a855f7,
            #c084fc,
            #e9d5ff
        );

        -webkit-background-clip: text;

        -webkit-text-fill-color: transparent;

        letter-spacing: 2px;

        margin-bottom: 15px;

        text-shadow:
        0px 0px 25px rgba(168,85,247,0.35);
    }

    /* =========================================
       SUBTÍTULOS
    ========================================= */

    h2, h3 {

        color: #f5f3ff;
    }

    /* =========================================
       TEXTOS
    ========================================= */

    p, label, div {

        color: #d8d4fe;
    }

    /* =========================================
       INPUTS
    ========================================= */

    .stTextInput input,
    .stSelectbox div[data-baseweb="select"] {

        background-color: rgba(30,41,59,0.75);

        border: 1px solid rgba(168,85,247,0.2);

        border-radius: 12px;

        color: white;
    }

    /* =========================================
       BOTÕES
    ========================================= */

    .stButton button {

        background:
        linear-gradient(
            90deg,
            #7c3aed,
            #a855f7
        );

        color: white;

        border: none;

        border-radius: 10px;

        height: 48px;

        width: 100%;

        font-weight: 700;

        transition: 0.3s;
    }

    .stButton button:hover {

        transform: scale(1.02);

        box-shadow:
        0px 0px 20px rgba(168,85,247,0.4);
    }

    /* =========================================
       MÉTRICAS / CARDS
    ========================================= */

    div[data-testid="stMetric"] {

        background-color: rgba(22,27,34,0.65);

        border: 1px solid rgba(168,85,247,0.15);

        padding: 20px;

        border-radius: 16px;

        backdrop-filter: blur(12px);
    }

    /* =========================================
       EXPANDERS
    ========================================= */

    .streamlit-expanderHeader {

        background-color: rgba(22,27,34,0.75);

        border-radius: 12px;

        border:
        1px solid rgba(168,85,247,0.12);
    }

    /* =========================================
       SCROLLBAR
    ========================================= */

    ::-webkit-scrollbar {

        width: 10px;
    }

    ::-webkit-scrollbar-thumb {

        background: #7c3aed;

        border-radius: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)

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
