import streamlit as st

# =====================================
# IMPORTS
# =====================================

from Scanners.semgrep import rodar_semgrep

from IAs.risk_score import calcular_criticidade

from Database.db import (
    criar_tabela,
    salvar_ativo,
    listar_ativos_db
)

# =====================================
# CONFIGURAÇÃO
# =====================================

st.set_page_config(
    page_title="ASPM Platform",
    page_icon="🔐",
    layout="wide"
)

# =====================================
# BANCO
# =====================================

criar_tabela()

# =====================================
# CSS / VISUAL
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

    h1, #titulo {

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

# =====================================
# TÍTULO
# =====================================

st.markdown(
    """
    <div>
        <p id='titulo'>ASPM Platform</p>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <p style='
    text-align:center;
    font-size:20px;
    margin-bottom:40px;'>

    Application Security Posture Management

    </p>
    """,
    unsafe_allow_html=True
)

# =====================================
# CADASTRO
# =====================================

st.markdown(
    """
    <div style='
        font-size:32px;
        font-weight:700;
        margin-top:20px;
        margin-bottom:20px;
        color:#f5f3ff;
    '>

    Cadastro de Ativos

    </div>
    """,
    unsafe_allow_html=True
)

nome = st.text_input(
    "Nome do ativo"
)

tipo = st.selectbox(
    "Tipo do ativo",
    [
        "API",
        "Aplicação",
        "Repositório"
    ]
)

url = st.text_input(
    "URL / Caminho do ativo"
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
# BOTÃO
# =====================================

if st.button("🔍 Analisar Ativo"):

    with st.spinner(
        "Analisando ativo..."
    ):

        resultado_scanner = ""

        if tipo == "Repositório":

            resultado_scanner = rodar_semgrep(
                url
            )

        criticidade, score = calcular_criticidade(
            tipo,
            ambiente,
            resultado_scanner
        )

        salvar_ativo(
            nome,
            tipo,
            url,
            ambiente,
            criticidade,
            score
        )

    st.success(
        "✅ Análise concluída!"
    )

    # =====================================
    # RESULTADO
    # =====================================

    st.markdown(
        """
        <div style='
            font-size:32px;
            font-weight:700;
            margin-top:20px;
            margin-bottom:20px;
            color:#f5f3ff;
        '>

        Resultado da Análise

        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Criticidade",
            criticidade
        )

    with col2:

        st.metric(
            "Risk Score",
            score
        )

    st.write(f"Ativo analisado: {nome}")

    # =====================================
    # RESULTADO SCANNER
    # =====================================

    if resultado_scanner:

        st.markdown(
            """
            <div style='
                font-size:26px;
                font-weight:700;
                margin-top:20px;
                margin-bottom:20px;
                color:#f5f3ff;
            '>

            Resultado do Scanner

            </div>
            """,
            unsafe_allow_html=True
        )

        st.code(resultado_scanner)

# =====================================
# INVENTÁRIO
# =====================================

st.markdown(
    """
    <div style='
        font-size:32px;
        font-weight:700;
        margin-top:30px;
        margin-bottom:20px;
        color:#f5f3ff;
    '>

    📊 Inventário de Ativos

    </div>
    """,
    unsafe_allow_html=True
)

ativos = listar_ativos_db()

if ativos:

    for ativo in ativos:

        with st.expander(
            f"🔎 {ativo[1]}"
        ):

            st.write(
                f"Tipo: {ativo[2]}"
            )

            st.write(
                f"URL: {ativo[3]}"
            )

            st.write(
                f"Ambiente: {ativo[4]}"
            )

            st.write(
                f"Criticidade: {ativo[5]}"
            )

            st.write(
                f"Risk Score: {ativo[6]}"
            )

            if ativo[5] == "Crítica":

                st.error(
                    "⚠️ Risco Crítico"
                )

            elif ativo[5] == "Alta":

                st.warning(
                    "⚠️ Alto Risco"
                )

            else:

                st.success(
                    "✔ Risco Controlado"
                )

else:

    st.info(
        "Nenhum ativo cadastrado."
    )
