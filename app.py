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
        background: radial-gradient(circle at top, #2b0a3d 0%, #1e1b4b 25%, #111827 55%, #0d1117 100%);
        color: white;
    }
    section[data-testid="stSidebar"] {
        background-color: rgba(13,17,23,0.95);
        border-right: 1px solid rgba(168,85,247,0.15);
        backdrop-filter: blur(10px);
    }
    #titulo {
        font-size: 70px;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(90deg, #7c3aed, #a855f7, #c084fc, #e9d5ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 2px;
        margin-bottom: 15px;
        text-shadow: 0px 0px 25px rgba(168,85,247,0.35);
    }
    p, label, div { color: #d8d4fe; }
    .stTextInput input, .stSelectbox div[data-baseweb="select"] {
        background-color: rgba(30,41,59,0.75);
        border: 1px solid rgba(168,85,247,0.2);
        border-radius: 12px;
        color: white;
    }
    .stButton button {
        background: linear-gradient(90deg, #7c3aed, #a855f7);
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
        box-shadow: 0px 0px 20px rgba(168,85,247,0.4);
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
        border: 1px solid rgba(168,85,247,0.12);
    }
    ::-webkit-scrollbar { width: 10px; }
    ::-webkit-scrollbar-thumb { background: #7c3aed; border-radius: 10px; }
    </style>
    """,
    unsafe_allow_html=True
)

# =====================================
# TÍTULO
# =====================================
st.markdown("<div><p id='titulo'>ASPM Platform</p></div>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; font-size:20px; margin-bottom:40px;'>Application Security Posture Management</p>", unsafe_allow_html=True)

# =====================================
# CADASTRO
# =====================================
st.markdown("<div style='font-size:32px; font-weight:700; margin:20px 0; color:#f5f3ff;'>Cadastro de Ativos</div>", unsafe_allow_html=True)

nome = st.text_input("Nome do ativo")
tipo = st.selectbox("Tipo do ativo", ["API", "Aplicação", "Repositório"])
url = st.text_input("URL / Caminho do ativo")
ambiente = st.selectbox("Ambiente", ["Produção", "Homologação", "Desenvolvimento"])

# =====================================
# BOTÃO DE ANÁLISE
# =====================================
if st.button("🔍 Analisar Ativo"):
    resultado_sast = ""
    resultado_dast = ""
    houve_erro = False
    msg_erro = ""

    # Validação Básica
    if not url.strip():
        st.error("❌ URL inválida.")
        st.stop()

    if tipo in ["API", "Aplicação"] and not (url.startswith("http://") or url.startswith("https://")):
        st.error("❌ URL inválida. Utilize http:// ou https://")
        st.stop()

    # Execução das Análises
    with st.spinner("Executando análise de segurança..."):
        try:
            # --- SAST ---
            if tipo == "Repositório":
                resultado_sast = rodar_semgrep(url)

            # --- DAST ---
            if tipo in ["API", "Aplicação"]:
                resultado_dast = rodar_zap(url)
                if resultado_dast == "ERRO_PROXY_ZAP":
                    msg_erro = "❌ Erro ao conectar no OWASP ZAP."
                    houve_erro = True
            
            # --- IA GEMINI (Só executa se não houver erro prévio) ---
            if not houve_erro:
                criticidade, score, analise_ia = analisar_vulnerabilidades(
                    tipo, ambiente, resultado_sast, resultado_dast
                )
        except Exception as e:
            msg_erro = f"❌ Erro inesperado: {e}"
            houve_erro = True

    
    if houve_erro:
        st.error(msg_erro)
        st.stop()

    salvar_ativo(nome, tipo, url, ambiente, criticidade, score)
    st.success("✅ Análise concluída!")

   
    st.markdown("<div style='font-size:32px; font-weight:700; margin:20px 0; color:#f5f3ff;'>Resultado da Análise</div>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Criticidade", criticidade)
    with col2:
        st.metric("Risk Score", score)

    st.write(f"Ativo analisado: **{nome}**")

    
    st.markdown("<div style='font-size:26px; font-weight:700; margin:20px 0; color:#f5f3ff;'>Análise Inteligente da IA</div>", unsafe_allow_html=True)
    st.write(analise_ia)

# =====================================
# INVENTÁRIO DE ATIVOS
# =====================================
st.markdown("<div style='font-size:32px; font-weight:700; margin-top:30px; color:#f5f3ff;'>📊 Inventário de Ativos</div>", unsafe_allow_html=True)

ativos = listar_ativos_db()
if ativos:
    # KPIs rápidos
    total_ativos = len(ativos)
    ativos_criticos = sum(1 for a in ativos if a[5] == "Crítica")
    media_score = round(sum(a[6] for a in ativos) / total_ativos, 1) if total_ativos > 0 else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total de Ativos", total_ativos)
    col2.metric("Ativos Críticos", ativos_criticos)
    col3.metric("Risk Score Médio", media_score)

    # Listagem em Expansores
    for ativo in ativos:
        with st.expander(f"🔎 {ativo[1]} - {ativo[5]}"):
            st.write(f"**Tipo:** {ativo[2]} | **Ambiente:** {ativo[4]}")
            st.write(f"**URL:** {ativo[3]}")
            st.write(f"**Score:** {ativo[6]}")
            
            if ativo[5] == "Crítica": st.error("⚠️ Risco Crítico")
            elif ativo[5] == "Alta": st.warning("⚠️ Alto Risco")
            else: st.success("✔ Risco Controlado")
else:
    st.info("Nenhum ativo cadastrado.")
