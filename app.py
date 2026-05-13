import streamlit as st

# =====================================
# IMPORTS
# =====================================

from Scanners.owaspzap import rodar_zap
from Scanners.semgrep import rodar_semgrep

from IAs.gemini import analisar_vulnerabilidades

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

    section[data-testid="stSidebar"] {

        background-color: rgba(13,17,23,0.95);

        border-right:
        1px solid rgba(168,85,247,0.15);

        backdrop-filter: blur(10px);
    }

    #titulo {

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

    p, label, div {

        color: #d8d4fe;
    }

    .stTextInput input,
    .stSelectbox div[data-baseweb="select"] {

        background-color: rgba(30,41,59,0.75);

        border: 1px solid rgba(168,85,247,0.2);

        border-radius: 12px;

        color: white;
    }

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

    div[data-testid="stMetric"] {

        background-color: rgba(22,27,34,0.65);

        border: 1px solid rgba(168,85,247,0.15);

        padding: 20px;

        border-radius: 16px;

        backdrop-filter: blur(12px);
    }

    .streamlit-expanderHeader {

        background-color: rgba(22,27,34,0.75);

        border-radius: 12px;

        border:
        1px solid rgba(168,85,247,0.12);
    }

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

    resultado_sast = ""
    resultado_dast = ""

    # =====================================
    # VALIDAÇÃO URL
    # =====================================

    if not url.strip():

        st.error(
            "❌ URL inválida."
        )

        st.stop()

    if (
        tipo == "API"
        or tipo == "Aplicação"
    ):

        if (
            not url.startswith("http://")
            and not url.startswith("https://")
        ):

            st.error(
                "❌ URL inválida. Utilize http:// ou https://"
            )

            st.stop()

    # =====================================
    # EXECUTAR ANÁLISES
    # =====================================

    with st.spinner(
        "Executando análise de segurança..."
    ):

        # =====================================
        # SAST
        # =====================================

        if tipo == "Repositório":

            try:

                resultado_sast = rodar_semgrep(
                    url
                )

            except Exception as erro:

                resultado_sast = (
                    f"Erro no Semgrep: {erro}"
                )

        # =====================================
        # DAST
        # =====================================

        if (
            tipo == "API"
            or tipo == "Aplicação"
        ):

            try:

                resultado_dast = rodar_zap(
                    url
                )

                # =====================================
                # ERRO ZAP
                # =====================================

                if resultado_dast == "ERRO_PROXY_ZAP":

                    st.error(
                        "❌ Erro ao conectar no OWASP ZAP."
                    )

                    st.stop()

            except Exception as erro:

                st.error(
                    f"Erro no ZAP: {erro}"
                )

                st.stop()

        # =====================================
        # IA GEMINI
        # =====================================

        try:

            criticidade, score, analise_ia = analisar_vulnerabilidades(
                tipo,
                ambiente,
                resultado_sast,
                resultado_dast
            )

        except Exception as erro:

            st.error(
                f"Erro na IA Gemini: {erro}"
            )

            st.stop()

    # =====================================
    # SALVAR NO BANCO
    # =====================================

    salvar_ativo(
        nome,
        tipo,
        url,
        ambiente,
        criticidade,
        score
    )

    # =====================================
    # SUCESSO
    # =====================================

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

    st.write(
        f"Ativo analisado: {nome}"
    )

    # =====================================
    # ANÁLISE IA
    # =====================================

    st.markdown(
        """
        <div style='
            font-size:26px;
            font-weight:700;
            margin-top:20px;
            margin-bottom:20px;
            color:#f5f3ff;
        '>

        Análise Inteligente da IA

        </div>
        """,
        unsafe_allow_html=True
    )

    st.write(
        analise_ia
    )

    # =====================================
    # RESULTADO SAST
    # =====================================

    if resultado_sast:

        st.markdown(
            """
            <div style='
                font-size:26px;
                font-weight:700;
                margin-top:20px;
                margin-bottom:20px;
                color:#f5f3ff;
            '>

            Resultado SAST (Semgrep)

            </div>
            """,
            unsafe_allow_html=True
        )

        st.code(
            str(resultado_sast)
        )

    # =====================================
    # RESULTADO DAST
    # =====================================

    if resultado_dast:

        st.markdown(
            """
            <div style='
                font-size:26px;
                font-weight:700;
                margin-top:20px;
                margin-bottom:20px;
                color:#f5f3ff;
            '>

            Resultado DAST (OWASP ZAP)

            </div>
            """,
            unsafe_allow_html=True
        )

        st.code(
            str(resultado_dast)
        )

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

# =====================================
# KPIs
# =====================================

total_ativos = len(ativos)

ativos_criticos = 0

soma_scores = 0

for ativo in ativos:

    soma_scores += ativo[6]

    if ativo[5] == "Crítica":

        ativos_criticos += 1

if total_ativos > 0:

    media_score = round(
        soma_scores / total_ativos,
        1
    )

else:

    media_score = 0

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Total de Ativos",
        total_ativos
    )

with col2:

    st.metric(
        "Ativos Críticos",
        ativos_criticos
    )

with col3:

    st.metric(
        "Risk Score Médio",
        media_score
    )

# =====================================
# LISTAGEM
# =====================================

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
