import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_option_menu import option_menu
import base64
import os

# =====================================
# IMPORTS DOS SEUS MÓDULOS
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
# CONFIGURAÇÃO E FUNÇÃO DE LOGO
# =====================================
st.set_page_config(
    page_title="ASPM Platform",
    page_icon="logo.ico",
    layout="wide"
)

# =====================================
# BANCO
# =====================================
criar_tabela()

def get_base64_image(image_path):
    if os.path.exists(image_path):
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    return None

caminho_logo = "logo.png" 
logo_base64 = get_base64_image(caminho_logo)

st.markdown(
    f"""
    <style>
    .stApp {{
        background: var(--background-color);
        transition: all 0.8s ease;
    }}
    
     section[data-testid="stSidebar"] {{
        background: var(--secondary-background-color);
        border-right: 1px solid rgba(168,85,247,0.15);
        backdrop-filter: blur(10px);
        transition: all 0.4s ease;
    }}
    
    .logo-container {{
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 0px 0px 50px 0px;
    }}

    .logo-img {{
        width: 250px;
        filter: drop-shadow(0px 0px 12px rgba(168,85,247,0.3));
    }}

    #titulo-principal {{
        font-size: 50px;
        font-weight: 800;
        background: linear-gradient(
            90deg,
            #7c3aed,
            #a855f7,
            #c084fc,
            #e9d5ff
        );
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 2px;
        margin-bottom: 5px;
        text-shadow: 0px 0px 25px rgba(168,85,247,0.35);
    }}

    p, label, div {{
        color: var(--text-color);
        transition: 0.2s ease;
    }}

    .stTextInput input,
    .stSelectbox div[data-baseweb="select"] {{
        background-color: var(--secondary-background-color) !important;
        border: 1px solid rgba(168,85,247,0.2) !important;
        border-radius: 12px;
        transition: 0.4s ease;
        color: var(--text-color) !important;
    }}

    .stButton button {{
        background: linear-gradient(
            90deg,
            #7c3aed,
            #a855f7
        ) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px;
        height: 48px;
        width: 100%;
        font-weight: 700;
        transition: 0.3s ease;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# =====================================
# MENU LATERAL
# =====================================
with st.sidebar:
    if logo_base64:
        st.markdown(f"""
            <div class="logo-container">
                <img src="data:image/png;base64,{logo_base64}" class="logo-img">
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("<h1 style='text-align:center;'>🛡️ ASPM</h1>", unsafe_allow_html=True)
    
    selecionado = option_menu(
        menu_title=None, 
        options=["Dashboard", "Análises", "Ativos", "Vulnerabilidades", "Relatórios", "Políticas", "Configurações"],
        icons=["house-fill", "graph-up-arrow", "pc-display","shield-exclamation", "file-earmark-text","clipboard-check","gear"],
        default_index=0,
        styles={
            "container": {"padding": "0!important",},
            "icon": {"color": "#c084fc", "font-size": "18px"}, 
            "nav-link": {
                "font-size": "16px", 
                "text-align": "left", 
                "margin":"5px 0px", 
                "--hover-color": "rgba(168,85,247,0.1)"
            },
            "nav-link-selected": {
                "background": "linear-gradient(90deg,#a41db8,#2d0b63)",
                "border-radius":"8px",
                "color": "white",
                "padding":"15px",
                "transition": "all 0.3s ease"
            },
        }
    )
    st.markdown("---")

st.sidebar.markdown(
    """
    <div style="
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px;
        border-radius: 10px;
        background: #050816;
        border: 3px solid #c084fc;
        cursor: pointer;
        margin-top: 20px;
    ">
        <i class="bi bi-box-arrow-right" style="color: #c084fc;"></i>
        <span style="color: #c084fc; font-weight: 600;">Sair</span>
    </div>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    """,
    unsafe_allow_html=True
)

# =====================================
# LÓGICA DE PÁGINAS
# =====================================

if selecionado == "Dashboard":
    st.markdown("<div><p id='titulo-principal'>ASPM PLATFORM</p></div>", unsafe_allow_html=True)
    st.markdown("<p style='font-size:18px; margin-bottom:40px; opacity: 0.8;'>Application Security Posture Management</p>", unsafe_allow_html=True)
    
    ativos = listar_ativos_db()
    
    if ativos:
        df = pd.DataFrame(ativos, columns=['id', 'nome', 'tipo', 'url', 'ambiente', 'criticidade', 'score', 'analise'])
        
        total = len(df)
        criticos = len(df[df['criticidade'] == 'Crítica'])
        altos = len(df[df['criticidade'] == 'Alta'])
        medios = len(df[df['criticidade'] == 'Média'])
        baixos = len(df[df['criticidade'] == 'Baixa'])

        def card_kpi(titulo, valor, cor, icone, subtext):
            st.markdown(f"""
                <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.1);
                    border-left: 5px solid {cor}; padding: 20px; border-radius: 12px; backdrop-filter: blur(10px); margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 14px; color: #d8d4fe;">{titulo}</span>
                        <span>{icone}</span>
                    </div>
                    <div style="font-size: 32px; font-weight: 800; margin: 10px 0;">{valor}</div>
                    <div style="font-size: 12px; color: {cor}; font-weight: 600;">{subtext}</div>
                </div>
            """, unsafe_allow_html=True)

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1: card_kpi("Total de Ativos", total, "#7c3aed", "📂", "Monitorados")
        with col2: card_kpi("Risco Crítico", criticos, "#ff4b4b", "🛡️", f"{(criticos/total*100):.1f}%" if total > 0 else "0%")
        with col3: card_kpi("Risco Alto", altos, "#ff8c00", "⚠️", f"{(altos/total*100):.1f}%" if total > 0 else "0%")
        with col4: card_kpi("Risco Médio", medios, "#ffd700", "🟡", f"{(medios/total*100):.1f}%" if total > 0 else "0%")
        with col5: card_kpi("Risco Baixo", baixos, "#00c853", "✅", f"{(baixos/total*100):.1f}%" if total > 0 else "0%")

        st.markdown("<br>", unsafe_allow_html=True)
        col_graf1, col_graf2 = st.columns([1, 2])

        with col_graf1:
            st.markdown("<p style='font-weight:700; font-size:20px;'>Distribuição de Riscos</p>", unsafe_allow_html=True)
            cores_map = {'Crítica': '#ff4b4b', 'Alta': '#ff8c00', 'Média': '#ffd700', 'Baixa': '#00c853'}
            fig_donut = px.pie(df, names='criticidade', hole=0.6, color='criticidade', color_discrete_map=cores_map)
            fig_donut.update_layout(showlegend=True, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
                                    margin=dict(t=10, b=10, l=10, r=10), font=dict(color="white"), height=300)
            st.plotly_chart(fig_donut, width='content')

        with col_graf2:
            st.markdown("<p style='font-weight:700; font-size:20px;'>Risco por Ambiente (Média de Score)</p>", unsafe_allow_html=True)
            df_env = df.groupby('ambiente')['score'].mean().round(1).reset_index()
            fig_bar = px.bar(df_env, x='score', y='ambiente', orientation='h', text='score')
            fig_bar.update_traces(marker_color='#3b82f6', textposition='inside')
            fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color="white"),
                                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False), height=300, margin=dict(r=20))
            st.plotly_chart(fig_bar, width='content')

        st.markdown("<p style='font-weight:700; font-size:24px; margin-top:30px;'>Ativos Recentes</p>", unsafe_allow_html=True)
        st.dataframe(df[['nome', 'tipo', 'ambiente', 'criticidade', 'score']].sort_values(by='score', ascending=False),
                     width='content', hide_index=True)
    else:
        st.info("Nenhum ativo analisado ainda. Vá para a aba 'Análises' para começar.")

elif selecionado == "Análises":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Nova Análise de Ativo</div>", unsafe_allow_html=True)
    
    nome = st.text_input("Nome do ativo")
    tipo = st.selectbox("Tipo do ativo", ["API", "Aplicação", "Repositório"])
    url = st.text_input("URL / Caminho do ativo")
    ambiente = st.selectbox("Ambiente", ["Produção", "Homologação", "Desenvolvimento"])

    if st.button("🔍 Iniciar Análise"):
        if not url.strip():
            st.error("❌ URL inválida.")
        else:
            with st.spinner("Executando análise de segurança..."):
                try:
                    res_sast = rodar_semgrep(url) if tipo == "Repositório" else ""
                    res_dast = rodar_zap(url) if tipo in ["API", "Aplicação"] else ""
                    
                    if res_dast == "ERRO_PROXY_ZAP":
                        st.error("❌ Erro ao conectar no OWASP ZAP.")
                    else:
                        crit, score, analise = analisar_vulnerabilidades(tipo, url, ambiente, res_sast, res_dast)
                        
                        salvar_ativo(nome, tipo, url, ambiente, crit, score, analise)
                        st.success("✅ Análise concluída!")
                        st.metric("Risk Score", score)
                        st.write(analise)
                except Exception as e:
                    st.error(f"Erro inesperado: {e}")

elif selecionado == "Ativos":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Inventário de Ativos</div>", unsafe_allow_html=True)
    ativos = listar_ativos_db()
    if ativos:
        for a in ativos:
            with st.expander(f"🔎 {a[1]} - {a[5]}"):
                st.write(f"**Tipo:** {a[2]} | **Ambiente:** {a[4]} | **Score:** {a[6]}")
                st.write(f"**URL:** {a[3]}")
    else:
        st.info("Nenhum ativo cadastrado.")

elif selecionado == "Vulnerabilidades":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Gestão de Vulnerabilidades</div>", unsafe_allow_html=True)
    
    ativos = listar_ativos_db()
    
    if ativos:
        opcoes_ativos = {f"{a[1]} - {a[4]}": a for a in ativos}
        
        ativo_selecionado = st.selectbox(
            "Selecione um ativo para visualizar os detalhes das vulnerabilidades:", 
            options=list(opcoes_ativos.keys())
        )
        
        if ativo_selecionado:
            dados_ativo = opcoes_ativos[ativo_selecionado]

            st.markdown("## 🔍 Vulnerabilidades encontradas")
            
            try:
                texto_completo = dados_ativo[7]
                
                if "---VULNS---" in texto_completo:
                    conteudo_vulns = texto_completo.split("---VULNS---")[1].split("---RELATORIO---")[0].strip()
                    st.markdown(conteudo_vulns)
                else:
                    
                    st.markdown(texto_completo)
                    
            except IndexError:
                st.warning("⚠️ O texto da análise está corrompido ou em formato antigo.")
elif selecionado == "Relatórios":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Relatórios de Segurança Executivos</div>", unsafe_allow_html=True)
    
    ativos = listar_ativos_db()
    if ativos:
        opcoes_ativos = {f"{a[1]} - {a[4]}": a for a in ativos}
        ativo_sel = st.selectbox("Selecione o ativo para o relatório:", options=list(opcoes_ativos.keys()))
        
        if ativo_sel:
            dados_ativo = opcoes_ativos[ativo_sel]
            texto_completo = dados_ativo[7]
            
            if "---RELATORIO---" in texto_completo:
                conteudo_relatorio = texto_completo.split("---RELATORIO---")[1].strip()
                st.markdown(conteudo_relatorio)
            else:
                st.info("Gere uma nova análise para este ativo para visualizar o relatório estruturado.")

    else:
        st.info("Nenhum ativo cadastrado. Faça uma análise primeiro.")