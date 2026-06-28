import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_option_menu import option_menu
import base64
import os
from Scanners.owaspzap import rodar_zap
from Scanners.semgrep import rodar_semgrep
from Scanners.trivy import rodar_trivy
from IAs.gemini import analisar_vulnerabilidades
from Database.db import (
    criar_tabela,
    salvar_ativo,
    listar_ativos_db,
    listar_alertas_ativos,
    resolver_alerta,
    listar_historico,
    deletar_ativo,
    get_intervalo_rescan,
    set_intervalo_rescan,
)
from Monitoring.scheduler import iniciar_scheduler, reiniciar_scheduler
from Auth.auth import (
    usuario_logado,
    autenticar,
    cadastrar_usuario,
    logout,
    render_cookie_manager,
)

st.set_page_config(
    page_title="ASPM Platform",
    page_icon="logo.ico",
    layout="wide"
)

criar_tabela()
render_cookie_manager()


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
    .stApp {{ background: var(--background-color); transition: all 0.8s ease; }}
    section[data-testid="stSidebar"] {{
        background: var(--secondary-background-color);
        border-right: 1px solid rgba(168,85,247,0.15);
        backdrop-filter: blur(10px);
        transition: all 0.4s ease;
    }}
    .logo-container {{
        display: flex; flex-direction: column;
        align-items: center; justify-content: center;
        padding: 0px 0px 50px 0px;
    }}
    .logo-img {{ width: 250px; filter: drop-shadow(0px 0px 12px rgba(168,85,247,0.3)); }}
    #titulo-principal {{
        font-size: 50px; font-weight: 800;
        background: linear-gradient(90deg, #7c3aed, #a855f7, #c084fc, #e9d5ff);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        letter-spacing: 2px; margin-bottom: 5px;
        text-shadow: 0px 0px 25px rgba(168,85,247,0.35);
    }}
    p, label, div {{ color: var(--text-color); transition: 0.2s ease; }}
    .stTextInput input, .stSelectbox div[data-baseweb="select"] {{
        background-color: var(--secondary-background-color) !important;
        border: 1px solid rgba(168,85,247,0.2) !important;
        border-radius: 12px; transition: 0.4s ease;
        color: var(--text-color) !important;
    }}
    div[data-baseweb="select"], div[data-baseweb="select"] * {{
        cursor: default !important;
    }}
    .stButton button {{
        background: linear-gradient(90deg, #7c3aed, #a855f7) !important;
        color: white !important; border: none !important;
        border-radius: 10px; height: 48px; width: 100%;
        font-weight: 700; transition: 0.3s ease;
    }}
    .vuln-card {{ border-radius: 12px; padding: 16px 20px; margin-bottom: 14px; border-left: 5px solid; }}
    .vuln-card.critico {{ background: rgba(255,75,75,0.08);  border-color: #ff4b4b; }}
    .vuln-card.alto    {{ background: rgba(255,140,0,0.08);  border-color: #ff8c00; }}
    .vuln-card.medio   {{ background: rgba(255,215,0,0.08);  border-color: #ffd700; }}
    .vuln-card.baixo   {{ background: rgba(0,200,83,0.08);   border-color: #00c853; }}
    .vuln-card-title {{ font-size:15px; font-weight:700; margin-bottom:10px; display:flex; align-items:center; gap:8px; }}
    .vuln-card-title.critico {{ color: #ff4b4b; }}
    .vuln-card-title.alto    {{ color: #ff8c00; }}
    .vuln-card-title.medio   {{ color: #ffd700; }}
    .vuln-card-title.baixo   {{ color: #00c853; }}
    .vuln-item {{
        font-size:13px; padding:6px 0px 6px 12px;
        border-bottom:1px solid rgba(255,255,255,0.05);
        line-height:1.5; color:var(--text-color); opacity:0.9;
    }}
    .vuln-item:last-child {{ border-bottom: none; }}
    .vuln-divider {{ border: none; border-top: 1px solid rgba(255,255,255,0.08); margin: 24px 0; }}
    </style>
    """,
    unsafe_allow_html=True
)


def _tela_login_cadastro():
    col_esq, col_centro, col_dir = st.columns([1, 1.2, 1])
    with col_centro:
        if logo_base64:
            st.markdown(f"""
                <div class="logo-container">
                    <img src="data:image/png;base64,{logo_base64}" class="logo-img">
                </div>
            """, unsafe_allow_html=True)

        aba_login, aba_cadastro = st.tabs(["Entrar", "Criar conta"])

        with aba_login:
            with st.form("form_login"):
                username = st.text_input("Usuário")
                senha = st.text_input("Senha", type="password")
                enviado = st.form_submit_button("Entrar", width='stretch')

            if enviado:
                sucesso, mensagem = autenticar(username.strip(), senha)
                if sucesso:
                    st.success(mensagem)
                    st.rerun()
                else:
                    st.error(mensagem)

        with aba_cadastro:
            with st.form("form_cadastro"):
                novo_nome = st.text_input("Nome completo")
                novo_username = st.text_input("Usuário", key="cad_username")
                novo_email = st.text_input("E-mail")
                nova_senha = st.text_input("Senha", type="password", key="cad_senha")
                confirmar_senha = st.text_input("Confirmar senha", type="password")
                enviado_cadastro = st.form_submit_button("Criar conta", width='stretch')

            if enviado_cadastro:
                if nova_senha != confirmar_senha:
                    st.error("As senhas não coincidem.")
                else:
                    sucesso, mensagem = cadastrar_usuario(
                        novo_username.strip(), novo_email.strip(), nova_senha, novo_nome.strip()
                    )
                    if sucesso:
                        st.success(mensagem)
                    else:
                        st.error(mensagem)

    st.stop()


sessao = usuario_logado()
if sessao is None:
    _tela_login_cadastro()

usuario_id   = sessao["usuario_id"]
nome_usuario = sessao["nome"] or sessao["username"]


if "scheduler_iniciado" not in st.session_state:
    iniciar_scheduler()
    st.session_state["scheduler_iniciado"] = True


with st.sidebar:
    st.markdown("""
        <style>
        .st-key-logout_wrapper button {
            background: transparent !important;
            background-image: none !important;
            background-color: transparent !important;
            border: 2px solid #c084fc !important;
            color: #c084fc !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            margin-top: 20px;
            box-shadow: none !important;
        }
        .st-key-logout_wrapper button:hover {
            background: rgba(168,85,247,0.12) !important;
            background-color: rgba(168,85,247,0.12) !important;
            border-color: #e9d5ff !important;
            color: #e9d5ff !important;
        }
        </style>
    """, unsafe_allow_html=True)

    if logo_base64:
        st.markdown(f"""
            <div class="logo-container">
                <img src="data:image/png;base64,{logo_base64}" class="logo-img">
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("<h1 style='text-align:center;'>🛡️ ASPM</h1>", unsafe_allow_html=True)

    st.markdown(
        f"<p style='text-align:center; opacity:0.7; margin-bottom:10px;'>Olá, <b>{nome_usuario}</b></p>",
        unsafe_allow_html=True
    )

    selecionado = option_menu(
        menu_title=None,
        options=["Dashboard", "Análises", "Ativos", "Vulnerabilidades", "Relatórios", "Políticas", "Configurações"],
        icons=["house-fill", "graph-up-arrow", "pc-display", "shield-exclamation", "file-earmark-text", "clipboard-check", "gear"],
        default_index=0,
        styles={
            "container": {"padding": "0!important"},
            "icon": {"color": "#c084fc", "font-size": "18px"},
            "nav-link": {"font-size": "16px", "text-align": "left", "margin": "5px 0px", "--hover-color": "rgba(168,85,247,0.1)"},
            "nav-link-selected": {
                "background": "linear-gradient(90deg,#a41db8,#2d0b63)",
                "border-radius": "8px", "color": "white",
                "padding": "15px", "transition": "all 0.3s ease"
            },
        }
    )
    st.markdown("---")

    with st.container(key="logout_wrapper"):
        if st.button("➜] Sair", key="btn_logout", width='stretch'):
            logout()


def _label_intervalo(minutos: int) -> str:
    if minutos < 60:
        return f"Últimos {minutos} min"
    elif minutos == 60:
        return "Última 1h"
    elif minutos < 1440:
        return f"Últimas {minutos // 60}h"
    else:
        return f"Últimas {minutos // 60}h"

def _render_cards(conteudo: str):
    import re
    if "[NIVEL:" not in conteudo:
        st.markdown(conteudo)
        return
    blocos = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', conteudo)
    i = 1
    while i < len(blocos) - 2:
        nivel      = blocos[i].strip()
        titulo     = blocos[i+1].strip()
        resto      = blocos[i+2]
        linhas     = resto.split("\n")
        itens      = [l[2:].strip() for l in linhas if l.strip().startswith("- ")]
        itens_html = "".join(f'<div class="vuln-item">• {item}</div>' for item in itens)
        st.markdown(f"""
            <div class="vuln-card {nivel}">
                <div class="vuln-card-title {nivel}">{titulo}</div>
                {itens_html}
            </div>
        """, unsafe_allow_html=True)
        i += 3

def _parse_blocos(texto_completo):
    sast_dast = ""
    sca       = ""
    relatorio = ""

    if "---VULNS_SAST_DAST---" in texto_completo:
        sast_dast = texto_completo.split("---VULNS_SAST_DAST---")[1].split("---VULNS_SCA---")[0].strip()
        sca       = texto_completo.split("---VULNS_SCA---")[1].split("---RELATORIO---")[0].strip()
    elif "---VULNS---" in texto_completo:
        bloco_vulns  = texto_completo.split("---VULNS---")[1].split("---RELATORIO---")[0].strip()
        MARCADOR_SCA = "### 📦 SCA (Trivy)"
        if MARCADOR_SCA in bloco_vulns:
            partes    = bloco_vulns.split(MARCADOR_SCA, 1)
            sast_dast = partes[0].strip()
            sca       = MARCADOR_SCA + "\n\n" + partes[1].strip()
        elif "[DIVISAO_SCA]" in bloco_vulns:
            partes    = bloco_vulns.split("[DIVISAO_SCA]")
            sast_dast = partes[0].strip()
            sca       = partes[1].strip()
        else:
            sast_dast = bloco_vulns
            sca       = "Nenhuma vulnerabilidade de dependências registrada neste formato."
    else:
        sast_dast = texto_completo

    if "---RELATORIO---" in texto_completo:
        relatorio = texto_completo.split("---RELATORIO---")[1].strip()

    return sast_dast, sca, relatorio

def _render_sast_dast(conteudo: str):
    if "---DIVISOR---" in conteudo:
        partes     = conteudo.split("---DIVISOR---")
        bloco_sast = partes[0].strip()
        bloco_dast = partes[1].strip()
        tem_sast   = "[NIVEL:" in bloco_sast
        tem_dast   = "[NIVEL:" in bloco_dast
        if tem_sast:
            _render_cards(bloco_sast)
        if tem_sast and tem_dast:
            st.markdown("<hr class='vuln-divider'>", unsafe_allow_html=True)
        if tem_dast:
            _render_cards(bloco_dast)
        if not tem_sast and not tem_dast:
            st.info("✅ Nenhuma vulnerabilidade encontrada.")
    else:
        _render_cards(conteudo)

def _exibir_abas(tipo: str, sast_dast_conteudo: str, sca_conteudo: str):
    if tipo == "Repositório":
        aba_sast, aba_sca = st.tabs(["🔬 Relatório SAST", "📦 Relatório SCA"])
        with aba_sast:
            _render_sast_dast(sast_dast_conteudo)
        with aba_sca:
            _render_cards(sca_conteudo)
    else:
        if "---DIVISOR---" in sast_dast_conteudo:
            bloco_dast = sast_dast_conteudo.split("---DIVISOR---")[1].strip()
        else:
            bloco_dast = sast_dast_conteudo
        aba_dast, = st.tabs(["🌐 Relatório DAST"])
        with aba_dast:
            _render_cards(bloco_dast)

def exibir_alertas_banner():
    alertas = listar_alertas_ativos(usuario_id)
    if not alertas:
        return

    cores = {
        "offline":  ("rgba(255,75,75,0.15)",  "#ff4b4b"),
        "anomalia": ("rgba(255,140,0,0.15)",   "#ff8c00"),
        "rescan":   ("rgba(124,58,237,0.15)",  "#a855f7"),
    }

    st.markdown("<p style='font-weight:700; font-size:16px; margin-bottom:8px;'>🔔 Alertas Ativos</p>", unsafe_allow_html=True)

    for alerta in alertas:
        alerta_id  = alerta[0]
        tipo       = alerta[2]
        mensagem   = alerta[3]
        data       = alerta[4]
        bg, border = cores.get(tipo, ("rgba(255,255,255,0.05)", "#ffffff"))
        col_msg, col_btn = st.columns([9, 1])
        with col_msg:
            st.markdown(f"""
                <div style="background:{bg}; border-left:4px solid {border};
                    padding:10px 16px; border-radius:8px; margin-bottom:6px; font-size:13px;">
                    {mensagem} &nbsp;&nbsp;
                    <span style="opacity:0.5; font-size:11px;">{data}</span>
                </div>
            """, unsafe_allow_html=True)
        with col_btn:
            if st.button("✓", key=f"resolve_{alerta_id}", help="Marcar como resolvido"):
                resolver_alerta(usuario_id, alerta_id)
                st.rerun()

    st.markdown("---")


if selecionado == "Dashboard":
    st.markdown("<div><p id='titulo-principal'>ASPM PLATFORM</p></div>", unsafe_allow_html=True)
    st.markdown("<p style='font-size:18px; margin-bottom:40px; opacity:0.8;'>Application Security Posture Management</p>", unsafe_allow_html=True)

    exibir_alertas_banner()
    ativos = listar_ativos_db(usuario_id)

    if ativos:
        df = pd.DataFrame(ativos, columns=[
            'id', 'usuario_id', 'nome', 'tipo', 'url', 'ambiente',
            'criticidade', 'score', 'analise', 'ultima_analise'
        ])
        df = df[df['criticidade'] != 'Erro']
        df['criticidade'] = df['criticidade'].replace('Alto', 'Alta')

        if df.empty:
            st.info("Nenhum ativo analisado ainda. Vá para a aba 'Análises' para começar.")
        else:
            total    = len(df)
            criticos = len(df[df['criticidade'] == 'Crítica'])
            altos    = len(df[df['criticidade'] == 'Alta'])
            medios   = len(df[df['criticidade'] == 'Média'])
            baixos   = len(df[df['criticidade'] == 'Baixa'])

            def card_kpi(titulo, valor, cor, icone, subtext):
                st.markdown(f"""
                    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.1);
                        border-left:5px solid {cor}; padding:20px; border-radius:12px;
                        backdrop-filter:blur(10px); margin-bottom:20px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:14px; color:#d8d4fe;">{titulo}</span>
                            <span>{icone}</span>
                        </div>
                        <div style="font-size:32px; font-weight:800; margin:10px 0;">{valor}</div>
                        <div style="font-size:12px; color:{cor}; font-weight:600;">{subtext}</div>
                    </div>
                """, unsafe_allow_html=True)

            col1, col2, col3, col4, col5 = st.columns(5)
            with col1: card_kpi("Total de Ativos", total,    "#7c3aed", "📂", "Monitorados")
            with col2: card_kpi("Risco Crítico",   criticos, "#ff4b4b", "🛡️", f"{(criticos/total*100):.1f}%" if total > 0 else "0%")
            with col3: card_kpi("Risco Alto",       altos,    "#ff8c00", "⚠️", f"{(altos/total*100):.1f}%"    if total > 0 else "0%")
            with col4: card_kpi("Risco Médio",     medios,   "#ffd700", "🟡", f"{(medios/total*100):.1f}%"   if total > 0 else "0%")
            with col5: card_kpi("Risco Baixo",     baixos,   "#00c853", "✅", f"{(baixos/total*100):.1f}%"   if total > 0 else "0%")

            st.markdown("<br>", unsafe_allow_html=True)
            col_graf1, col_graf2, col_graf3 = st.columns([1, 1, 1])

            with col_graf1:
                st.markdown("<p style='font-weight:700; font-size:20px;'>Distribuição de Riscos</p>", unsafe_allow_html=True)
                cores_map = {'Crítica': '#ff4b4b', 'Alta': '#ff8c00', 'Média': '#ffd700', 'Baixa': '#00c853'}
                df_counts = df['criticidade'].value_counts().reset_index()
                df_counts.columns = ['criticidade', 'count']
                df_counts['label'] = df_counts.apply(lambda r: f"{r['criticidade']} ({r['count']})", axis=1)
                fig_donut = px.pie(
                    df_counts, names='label', values='count',
                    hole=0.55, color='criticidade', color_discrete_map=cores_map
                )
                fig_donut.update_traces(
                    textposition='inside', textinfo='percent',
                    textfont=dict(color='white', size=13),
                    hovertemplate='%{label}<extra></extra>'
                )
                fig_donut.update_layout(
                    showlegend=True,
                    legend=dict(orientation="v", x=1.05, y=0.5, font=dict(size=11, color="white")),
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    margin=dict(t=10, b=10, l=10, r=50),
                    font=dict(color="white"), height=300
                )
                st.plotly_chart(fig_donut, width='content')

            with col_graf2:
                intervalo_atual = get_intervalo_rescan()
                label_hist      = _label_intervalo(intervalo_atual)
                st.markdown(f"<p style='font-weight:700; font-size:20px;'>Evolução de Risco ({label_hist})</p>", unsafe_allow_html=True)
                historico = listar_historico(usuario_id, minutos=intervalo_atual)
                if historico:
                    df_hist = pd.DataFrame(historico, columns=['score_medio', 'data'])
                    df_hist['hora'] = pd.to_datetime(df_hist['data'], format="%d/%m/%Y %H:%M:%S").dt.strftime("%H:%M:%S")
                    fig_line = px.line(df_hist, x='hora', y='score_medio', markers=True)
                else:
                    fig_line = px.line()
                fig_line.update_traces(line_color='#7c3aed', line_width=3, marker=dict(size=8, color='#a855f7'))
                fig_line.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color="white"), height=300,
                    xaxis=dict(showgrid=False, title=""),
                    yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', title="Risk Score Médio", range=[0, 100]),
                    margin=dict(t=10, b=10, l=10, r=10),
                    showlegend=False
                )
                st.plotly_chart(fig_line, width='content')

            with col_graf3:
                st.markdown("<p style='font-weight:700; font-size:20px;'>Risco por Ambiente</p>", unsafe_allow_html=True)
                df_env = df.groupby('ambiente')['score'].mean().round(0).reset_index()
                fig_bar = px.bar(df_env, x='score', y='ambiente', orientation='h', text='score')
                fig_bar.update_traces(marker_color='#3b82f6', textposition='outside', texttemplate='%{text}%')
                fig_bar.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color="white"),
                    xaxis=dict(showgrid=False, range=[0, 105], ticksuffix="%", tickvals=[0, 25, 50, 75, 100], title=""),
                    yaxis=dict(showgrid=False, title=""),
                    height=300, margin=dict(r=40, l=10, t=10, b=10)
                )
                st.plotly_chart(fig_bar, width='content')

            st.markdown("<p style='font-weight:700; font-size:24px; margin-top:30px;'>Ativos Recentes</p>", unsafe_allow_html=True)
            cores_crit = {'Crítica': '#ff4b4b', 'Alta': '#ff8c00', 'Média': '#ffd700', 'Baixa': '#00c853'}
            st.markdown("""
                <div style="display:grid; grid-template-columns:2fr 1.5fr 1.5fr 1fr 1fr 2fr;
                    padding:10px 16px; background:rgba(255,255,255,0.05);
                    border-radius:8px; font-size:13px; font-weight:700;
                    color:#c084fc; margin-bottom:4px;">
                    <span>Nome do Ativo</span><span>Tipo</span><span>Ambiente</span>
                    <span>Criticidade</span><span>Risk Score</span><span>Última Análise</span>
                </div>
            """, unsafe_allow_html=True)
            for _, row in df.sort_values(by='score', ascending=False).iterrows():
                cor    = cores_crit.get(row['criticidade'], '#ffffff')
                ultima = row['ultima_analise'] if row['ultima_analise'] else '—'
                st.markdown(f"""
                    <div style="display:grid; grid-template-columns:2fr 1.5fr 1.5fr 1fr 1fr 2fr;
                        padding:12px 16px; background:rgba(255,255,255,0.02);
                        border:1px solid rgba(255,255,255,0.06); border-radius:8px;
                        font-size:14px; margin-bottom:4px; align-items:center;">
                        <span style="font-weight:600;">{row['nome']}</span>
                        <span style="opacity:0.8;">{row['tipo']}</span>
                        <span style="opacity:0.8;">{row['ambiente']}</span>
                        <span><span style="background:{cor}22; color:{cor}; padding:4px 10px;
                            border-radius:20px; font-size:12px; font-weight:700;
                            border:1px solid {cor}55;">{row['criticidade']}</span></span>
                        <span style="color:{cor}; font-weight:800; font-size:16px;">{row['score']}</span>
                        <span style="opacity:0.6; font-size:12px;">{ultima}</span>
                    </div>
                """, unsafe_allow_html=True)
    else:
        st.info("Nenhum ativo analisado ainda. Vá para a aba 'Análises' para começar.")

elif selecionado == "Análises":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Análise de Ativo</div>", unsafe_allow_html=True)

    nome     = st.text_input("Nome do ativo")
    tipo     = st.selectbox("Tipo do ativo", ["API", "Aplicação", "Repositório"], filter_mode=None)
    url      = st.text_input("URL / Caminho do ativo")
    ambiente = st.selectbox("Ambiente", ["Produção", "Homologação", "Desenvolvimento"], filter_mode=None)

    if st.button("🔍 Iniciar Análise"):
        if not url.strip():
            st.error("❌ URL inválida.")
        else:
            with st.spinner("Executando análise de segurança..."):
                try:
                    res_sast = rodar_semgrep(url) if tipo == "Repositório"         else ""
                    res_dast = rodar_zap(url)      if tipo in ["API", "Aplicação"] else ""
                    res_sca  = rodar_trivy(url)    if tipo == "Repositório"        else ""

                    if res_dast == "ERRO_PROXY_ZAP":
                        st.error("❌ Erro ao conectar no OWASP ZAP.")
                        st.stop()

                    if isinstance(res_sast, str) and res_sast.startswith("ERRO:"):
                        st.error(f"❌ Erro no Semgrep: {res_sast.replace('ERRO:', '').strip()}")
                        st.stop()

                    if isinstance(res_sca, str) and res_sca.startswith("ERRO:"):
                        st.error(f"❌ Erro no Trivy: {res_sca.replace('ERRO:', '').strip()}")
                        st.stop()

                    crit, score, analise = analisar_vulnerabilidades(tipo, url, ambiente, res_sast, res_dast, res_sca)

                    if crit == "Erro":
                        st.error("❌ Erro na análise da IA. O ativo não foi salvo.")
                    else:
                        salvar_ativo(usuario_id, nome, tipo, url, ambiente, crit, score, analise)
                        st.success("✅ Análise concluída!")
                        st.metric("Risk Score", score)

                        sast_dast_conteudo, sca_conteudo, relatorio_conteudo = _parse_blocos(analise)

                        st.markdown("<br><h3>📋 Resultados Detalhados</h3>", unsafe_allow_html=True)
                        _exibir_abas(tipo, sast_dast_conteudo, sca_conteudo)

                        if relatorio_conteudo:
                            st.markdown("<br>", unsafe_allow_html=True)
                            st.markdown("---")
                            st.markdown(relatorio_conteudo)

                except Exception as e:
                    st.error(f"Erro inesperado: {e}")

elif selecionado == "Ativos":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Inventário de Ativos</div>", unsafe_allow_html=True)

    @st.dialog("Confirmar exclusão")
    def _modal_confirmar_exclusao(ativo_id, ativo_nome):
        st.warning(f"⚠️ Tem certeza que deseja excluir **{ativo_nome}**? Essa ação não pode ser desfeita.")
        col_sim, col_nao = st.columns(2)
        with col_sim:
            if st.button("✅ Sim, excluir", key=f"btn_confirma_{ativo_id}", width='stretch'):
                deletar_ativo(usuario_id, ativo_id)
                st.success(f"Ativo '{ativo_nome}' excluído com sucesso!")
                st.rerun()
        with col_nao:
            if st.button("❌ Cancelar", key=f"btn_cancela_{ativo_id}", width='stretch'):
                st.rerun()

    ativos = listar_ativos_db(usuario_id)
    if ativos:
        st.markdown("""
            <style>
            div[data-testid="stButton"] button[title="Excluir ativo"] {
                background: transparent !important;
                background-image: none !important;
                background-color: transparent !important;
                border: 2px solid #ff4b4b !important;
                color: #ff4b4b !important;
                border-radius: 8px !important;
                height: 38px !important;
                width: 38px !important;
                min-width: 38px !important;
                padding: 0px !important;
                box-shadow: none !important;
            }
            div[data-testid="stButton"] button[title="Excluir ativo"]:hover {
                background: rgba(255,75,75,0.12) !important;
                background-color: rgba(255,75,75,0.12) !important;
                border-color: #ff6b6b !important;
            }
            </style>
        """, unsafe_allow_html=True)

        for a in ativos:
            ativo_id   = a[0]
            ativo_nome = a[2]

            col_titulo, col_lixeira = st.columns([20, 1], vertical_alignment="center")

            with col_titulo:
                with st.expander(f"🔎 {ativo_nome} - {a[6]}"):
                    st.write(f"**Tipo:** {a[3]} | **Ambiente:** {a[5]} | **Score:** {a[7]}")
                    st.write(f"**URL:** {a[4]}")

            with col_lixeira:
                if st.button("🗑️", key=f"btn_excluir_{ativo_id}", help="Excluir ativo"):
                    _modal_confirmar_exclusao(ativo_id, ativo_nome)
    else:
        st.info("Nenhum ativo cadastrado.")

elif selecionado == "Vulnerabilidades":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Gestão de Vulnerabilidades</div>", unsafe_allow_html=True)
    ativos = listar_ativos_db(usuario_id)
    if ativos:
        opcoes_ativos = {f"{a[2]} - {a[5]}": a for a in ativos}
        ativo_selecionado = st.selectbox(
            "Selecione um ativo para visualizar os detalhes das vulnerabilidades:",
            options=list(opcoes_ativos.keys()),
            filter_mode=None
        )
        if ativo_selecionado:
            dados_ativo = opcoes_ativos[ativo_selecionado]
            try:
                tipo_ativo = dados_ativo[3]
                sast_dast_conteudo, sca_conteudo, _ = _parse_blocos(dados_ativo[8])
                _exibir_abas(tipo_ativo, sast_dast_conteudo, sca_conteudo)
            except IndexError:
                st.warning("⚠️ O texto da análise está corrompido ou em formato antigo.")
    else:
        st.info("Nenhum ativo cadastrado. Faça uma análise primeiro para gerenciar vulnerabilidades.")

elif selecionado == "Relatórios":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px;'>Relatórios de Segurança Executivos</div>", unsafe_allow_html=True)
    ativos = listar_ativos_db(usuario_id)
    if ativos:
        opcoes_ativos = {f"{a[2]} - {a[5]}": a for a in ativos}
        ativo_sel = st.selectbox("Selecione o ativo para o relatório:", options=list(opcoes_ativos.keys()), filter_mode=None)
        if ativo_sel:
            dados_ativo = opcoes_ativos[ativo_sel]
            _, _, relatorio_conteudo = _parse_blocos(dados_ativo[8])
            if relatorio_conteudo:
                st.markdown(relatorio_conteudo)
                from gerar_pdf import gerar_pdf_relatorio
                ativo_dict = {
                    "nome": dados_ativo[2], "tipo": dados_ativo[3],
                    "url": dados_ativo[4], "ambiente": dados_ativo[5],
                    "criticidade": dados_ativo[6], "score": dados_ativo[7],
                    "ultima_analise": dados_ativo[9]
                }
                pdf_bytes = gerar_pdf_relatorio(ativo_dict, dados_ativo[8], nome_usuario)
                st.download_button(
                    label="📄 Baixar Relatório PDF",
                    data=pdf_bytes,
                    file_name=f"relatorio_{dados_ativo[2].replace(' ', '_')}.pdf",
                    mime="application/pdf"
                )
            else:
                st.info("Gere uma nova análise para visualizar o relatório.")
    else:
        st.info("Nenhum ativo cadastrado. Faça uma análise primeiro.")

elif selecionado == "Configurações":
    st.markdown("<div style='font-size:32px; font-weight:700; margin-bottom:20px; color:var(--text-color);'>Configurações</div>", unsafe_allow_html=True)
    st.markdown("### 🔄 Re-scan Manual")
    st.markdown("Force um novo scan em todos os seus ativos sem esperar o agendamento automático.")

    ativos = listar_ativos_db(usuario_id)

    if not ativos:
        st.warning("⚠️ Nenhum ativo cadastrado para re-escanear.")
    else:
        st.info(f"📋 {len(ativos)} ativo(s) serão re-escaneados.")
        if st.button("🔍 Re-escanear todos os ativos agora"):
            with st.spinner("Re-escaneando todos os ativos... Isso pode demorar alguns minutos."):
                try:
                    from Monitoring.monitor import rescan_automatico
                    rescan_automatico(usuario_id)
                    st.success("✅ Re-scan concluído! Volte ao Dashboard para ver os resultados atualizados.")
                except Exception as e:
                    st.error(f"❌ Erro durante o re-scan: {e}")

    st.markdown("---")
    st.markdown("### ⏱️ Agendamento de Re-scan Automático")
    st.markdown("Define de quanto em quanto tempo o sistema re-escaneia todos os ativos automaticamente.")

    intervalo_atual = get_intervalo_rescan()

    opcoes = {
        "A cada 30 minutos":  30,
        "A cada 1 hora":      60,
        "A cada 3 horas":    180,
        "A cada 6 horas":    360,
        "A cada 12 horas":   720,
        "A cada 24 horas":  1440,
    }

    label_atual = next((k for k, v in opcoes.items() if v == intervalo_atual), "A cada 1 hora")

    novo_label = st.selectbox(
        "Intervalo de re-scan:",
        options=list(opcoes.keys()),
        index=list(opcoes.keys()).index(label_atual),
        filter_mode=None
    )

    if st.button("💾 Salvar agendamento"):
        novo_intervalo = opcoes[novo_label]
        set_intervalo_rescan(novo_intervalo)
        reiniciar_scheduler(novo_intervalo)
        st.info(f"O próximo re-scan automático será em até {novo_intervalo} minutos.")