import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_option_menu import option_menu

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
# CONFIGURAÇÃO
# =====================================
st.set_page_config(
    page_title="ASPM Platform",
    page_icon="🛡️",
    layout="wide"
)

# =====================================
# BANCO
# =====================================
criar_tabela()

# =====================================
# CSS / VISUAL (Consolidado)
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
    #titulo-principal {
        font-size: 50px;
        font-weight: 800;
        background: linear-gradient(90deg, #7c3aed, #a855f7, #c084fc, #e9d5ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 2px;
        margin-bottom: 5px;
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
    /* Estilização da Tabela Pandas */
    [data-testid="stDataFrame"] {
        background-color: rgba(22,27,34,0.4);
        border-radius: 12px;
        border: 1px solid rgba(168,85,247,0.1);
    }
    ::-webkit-scrollbar { width: 10px; }
    ::-webkit-scrollbar-thumb { background: #7c3aed; border-radius: 10px; }
    </style>
    """,
    unsafe_allow_html=True
)

# =====================================
# MENU LATERAL
# =====================================
with st.sidebar:
    st.markdown("<div style='text-align: center; margin-bottom: 20px;'><h1 style='color: white; font-size: 24px;'>🛡️ ASPM</h1><p style='color: #a855f7; font-size: 12px;'>PLATFORM</p></div>", unsafe_allow_html=True)
    
    selecionado = option_menu(
        menu_title=None, 
        options=["Dashboard", "Análises", "Ativos"],
        icons=["house", "search", "list-task"],
        menu_icon="cast",
        default_index=0,
        styles={
            "container": {"padding": "0!important", "background-color": "transparent"},
            "icon": {"color": "#a855f7", "font-size": "18px"}, 
            "nav-link": {
                "font-size": "16px", 
                "text-align": "left", 
                "margin":"5px 0px", 
                "--hover-color": "rgba(168,85,247,0.1)"
            },
            "nav-link-selected": {
                "background-color": "rgba(168,85,247,0.2)", 
                "border-left": "4px solid #a855f7"
            },
        }
    )
    st.markdown("---")
    st.markdown("<p style='text-align: center; font-size: 12px;'>Logado como Admin</p>", unsafe_allow_html=True)

# =====================================
# LÓGICA DE PÁGINAS
# =====================================

if selecionado == "Dashboard":
    # --- TÍTULO ---
    st.markdown("<div><p id='titulo-principal'>ASPM PLATFORM</p></div>", unsafe_allow_html=True)
    st.markdown("<p style='font-size:18px; margin-bottom:40px; opacity: 0.8;'>Application Security Posture Management</p>", unsafe_allow_html=True)

    # --- DADOS ---
    ativos = listar_ativos_db()
    
    if ativos:
        # Converter para DataFrame para facilitar gráficos
        df = pd.DataFrame(ativos, columns=['id', 'nome', 'tipo', 'url', 'ambiente', 'criticidade', 'score'])
        
        total = len(df)
        criticos = len(df[df['criticidade'] == 'Crítica'])
        altos = len(df[df['criticidade'] == 'Alta'])
        medios = len(df[df['criticidade'] == 'Média'])
        baixos = len(df[df['criticidade'] == 'Baixa'])

        # --- CARDS KPI ---
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

        # --- GRÁFICOS ---
        st.markdown("<br>", unsafe_allow_html=True)
        col_graf1, col_graf2 = st.columns([1, 2])

        with col_graf1:
            st.markdown("<p style='font-weight:700; font-size:20px;'>Distribuição de Riscos</p>", unsafe_allow_html=True)
            cores_map = {'Crítica': '#ff4b4b', 'Alta': '#ff8c00', 'Média': '#ffd700', 'Baixa': '#00c853'}
            fig_donut = px.pie(df, names='criticidade', hole=0.6, color='criticidade', color_discrete_map=cores_map)
            fig_donut.update_layout(showlegend=True, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
                                    margin=dict(t=10, b=10, l=10, r=10), font=dict(color="white"), height=300)
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_graf2:
            st.markdown("<p style='font-weight:700; font-size:20px;'>Risco por Ambiente (Média de Score)</p>", unsafe_allow_html=True)
            
            # Arredondando o score para ficar limpo no gráfico
            df_env = df.groupby('ambiente')['score'].mean().round(1).reset_index()
            
            # Gráfico de barras na cor AZUL (#3b82f6)
            fig_bar = px.bar(df_env, x='score', y='ambiente', orientation='h', text='score')
            
            # Atualizando a cor e posição do texto
            fig_bar.update_traces(marker_color='#3b82f6', textposition='inside')
            
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)', 
                font=dict(color="white"),
                xaxis=dict(showgrid=False), 
                yaxis=dict(showgrid=False), 
                height=300, 
                margin=dict(r=20) # Margem para o texto não cortar no final
            )
            
            st.plotly_chart(fig_bar, use_container_width=True)

        # --- TABELA DE ATIVOS RECENTES ---
        st.markdown("<p style='font-weight:700; font-size:24px; margin-top:30px;'>Ativos Recentes</p>", unsafe_allow_html=True)
        st.dataframe(df[['nome', 'tipo', 'ambiente', 'criticidade', 'score']].sort_values(by='score', ascending=False),
                     use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum ativo analisado ainda. Vá para a aba 'Análises' para começar.")

elif selecionado == "Análises":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:#f5f3ff;'>Nova Análise de Ativo</div>", unsafe_allow_html=True)
    
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
                        crit, score, analise = analisar_vulnerabilidades(tipo, ambiente, res_sast, res_dast)
                        salvar_ativo(nome, tipo, url, ambiente, crit, score)
                        st.success("✅ Análise concluída!")
                        st.metric("Risk Score", score)
                        st.write(analise)
                except Exception as e:
                    st.error(f"Erro inesperado: {e}")

elif selecionado == "Ativos":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:#f5f3ff;'>Inventário de Ativos</div>", unsafe_allow_html=True)
    ativos = listar_ativos_db()
    if ativos:
        for a in ativos:
            with st.expander(f"🔎 {a[1]} - {a[5]}"):
                st.write(f"**Tipo:** {a[2]} | **Ambiente:** {a[4]} | **Score:** {a[6]}")
                st.write(f"**URL:** {a[3]}")
    else:
        st.info("Nenhum ativo cadastrado.")
