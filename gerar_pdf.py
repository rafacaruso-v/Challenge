import io
import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

ROXO_ESCURO  = colors.HexColor("#1e1b4b")
ROXO_MEDIO   = colors.HexColor("#7c3aed")
ROXO_CLARO   = colors.HexColor("#6d28d9")
CRITICO      = colors.HexColor("#dc2626")
ALTO         = colors.HexColor("#d97706")
MEDIO        = colors.HexColor("#dad60b")
BAIXO        = colors.HexColor("#15803d")
FUNDO_HEADER = colors.HexColor("#1e1b4b")
FUNDO_LINHA  = colors.HexColor("#f5f3ff")
FUNDO_CARD   = colors.HexColor("#faf5ff")
BORDA        = colors.HexColor("#ddd6fe")
TEXTO_ESCURO = colors.HexColor("#1e1b4b")
TEXTO_MEDIO  = colors.HexColor("#374151")
TEXTO_CLARO  = colors.HexColor("#6b7280")
BRANCO       = colors.white


def _cor_criticidade(crit: str):
    return {"Critica": CRITICO, "Alta": ALTO, "Média": MEDIO, "Baixa": BAIXO}.get(crit, TEXTO_CLARO)


def _estilos():
    return {
        "titulo": ParagraphStyle("titulo", fontName="Helvetica-Bold", fontSize=22,
            textColor=BRANCO, alignment=TA_LEFT, spaceAfter=2, leading=26),
        "subtitulo": ParagraphStyle("subtitulo", fontName="Helvetica", fontSize=10,
            textColor=colors.HexColor("#c4b5fd"), alignment=TA_LEFT, spaceAfter=2, leading=13),
        "secao": ParagraphStyle("secao", fontName="Helvetica-Bold", fontSize=12,
            textColor=ROXO_MEDIO, spaceBefore=14, spaceAfter=6, leading=15),
        "corpo": ParagraphStyle("corpo", fontName="Helvetica", fontSize=9,
            textColor=TEXTO_MEDIO, leading=14, spaceAfter=4),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
            textColor=TEXTO_CLARO, spaceAfter=2, leading=10),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11,
            textColor=ROXO_MEDIO, spaceBefore=10, spaceAfter=4, leading=14),
        "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10,
            textColor=ROXO_CLARO, spaceBefore=8, spaceAfter=4, leading=13),
        "confidencial": ParagraphStyle("confidencial", fontName="Helvetica-Bold", fontSize=8,
            textColor=CRITICO, alignment=TA_RIGHT),
    }


def _linha_hr(story, cor=None):
    story.append(HRFlowable(width=170*mm, thickness=0.5,
                             color=cor or BORDA, spaceAfter=8, spaceBefore=4))


def _bloco_capa(story, ativo, nome_usuario, estilos):
    W = 170 * mm
    cor_crit = _cor_criticidade(ativo["criticidade"])

    for txt, st in [
        ("ASPM PLATFORM", estilos["titulo"]),
        ("Relatório de Segurança Executivo", estilos["subtitulo"]),
    ]:
        t = Table([[Paragraph(txt, st)]], colWidths=[W])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), FUNDO_HEADER),
            ("LEFTPADDING", (0,0), (-1,-1), 12),
            ("TOPPADDING", (0,0), (-1,-1), 10 if txt.startswith("ASPM") else 0),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8 if "Executivo" in txt else 4),
        ]))
        story.append(t)

    faixa = Table([[""]], colWidths=[W], rowHeights=[2*mm])
    faixa.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), ROXO_MEDIO)]))
    story.append(faixa)
    story.append(Spacer(1, 10))

    cl = ParagraphStyle("cl", fontName="Helvetica-Bold", fontSize=8, textColor=CRITICO)
    dt = ParagraphStyle("dt", fontName="Helvetica", fontSize=8, textColor=TEXTO_CLARO, alignment=TA_RIGHT)
    t = Table([[
        Paragraph("CONFIDENCIAL — USO INTERNO", cl),
        Paragraph(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}", dt),
    ]], colWidths=[85*mm, 85*mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    lbl = ParagraphStyle("lbl2", fontName="Helvetica-Bold", fontSize=8, textColor=TEXTO_CLARO, alignment=TA_CENTER)
    val = ParagraphStyle("val2", fontName="Helvetica", fontSize=9, textColor=TEXTO_ESCURO, alignment=TA_CENTER)
    cst = ParagraphStyle("cst", fontName="Helvetica-Bold", fontSize=9, textColor=cor_crit, alignment=TA_CENTER)
    sst = ParagraphStyle("sst", fontName="Helvetica-Bold", fontSize=10, textColor=cor_crit, leading=14, alignment=TA_CENTER)

    meta = [
        [Paragraph("Ativo", lbl), Paragraph("Tipo", lbl), Paragraph("Ambiente", lbl),
         Paragraph("Criticidade", lbl), Paragraph("Risk Score", lbl), Paragraph("Ultima Analise", lbl)],
        [Paragraph(ativo["nome"], val), Paragraph(ativo["tipo"], val),
         Paragraph(ativo["ambiente"], val), Paragraph(ativo["criticidade"], cst),
         Paragraph(str(ativo["score"]), sst), Paragraph(ativo.get("ultima_analise", "-"), val)],
    ]
    t = Table(meta, colWidths=[35*mm, 22*mm, 28*mm, 28*mm, 22*mm, 35*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_LINHA),
        ("BACKGROUND",    (0,1), (-1,1), BRANCO),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("LINEBELOW",     (0,0), (-1,0),  0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        f'<b>URL / Caminho:</b> {ativo.get("url", "-")}',
        ParagraphStyle("url", fontName="Helvetica", fontSize=8, textColor=TEXTO_CLARO, leading=11)
    ))
    _linha_hr(story)

    story.append(Paragraph("1. Escopo e Metodologia", estilos["secao"]))
    _linha_hr(story)

    escopo_data = [
        [Paragraph("Periodo da Analise", lbl), Paragraph("Responsavel", lbl),
         Paragraph("Frameworks de Referencia", lbl)],
        [Paragraph(ativo.get("ultima_analise", datetime.now().strftime("%d/%m/%Y %H:%M")), val),
         Paragraph(nome_usuario, val),
         Paragraph("ISO 27001 | SOC2 Type II | CIS Benchmark", val)],
    ]
    te = Table(escopo_data, colWidths=[45*mm, 45*mm, 80*mm])
    te.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_LINHA),
        ("BACKGROUND",    (0,1), (-1,1), BRANCO),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(te)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Ferramentas Utilizadas", estilos["label"]))
    story.append(Spacer(1, 4))

    ferramentas = _ferramentas_por_tipo(ativo["tipo"])
    fer_data = [[
        Paragraph("<b>Ferramenta</b>", lbl),
        Paragraph("<b>Categoria</b>", lbl),
        Paragraph("<b>Descricao</b>", lbl),
        Paragraph("<b>Referencia</b>", lbl),
    ]]
    for f in ferramentas:
        fer_data.append([
            Paragraph(f[0], val), Paragraph(f[1], val),
            Paragraph(f[2], val), Paragraph(f[3], val),
        ])

    tf = Table(fer_data, colWidths=[30*mm, 25*mm, 75*mm, 40*mm])
    tf.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_HEADER),
        ("TEXTCOLOR",     (0,0), (-1,0), BRANCO),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [BRANCO, FUNDO_LINHA]),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(tf)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Criterios SOC2 Avaliados (Trust Service Criteria)", estilos["label"]))
    story.append(Spacer(1, 4))

    soc2 = [
        ["CC6 — Logical Access", "Controles de acesso lógico e autenticação"],
        ["CC7 — System Operations", "Monitoramento de vulnerabilidades e incidentes"],
        ["CC8 — Change Management", "Gestão de mudanças e deploys seguros"],
        ["A1 — Availability", "Disponibilidade e resiliência do sistema"],
        ["C1 — Confidentiality", "Proteção de dados confidenciais"],
        ["PI1 — Processing Integrity", "Integridade no processamento de resultados de scans e cálculo de risk score"],
    ]
    soc2_data = [[Paragraph("<b>Criterio</b>", lbl), Paragraph("<b>Descricao</b>", lbl)]]
    for s in soc2:
        soc2_data.append([
            Paragraph(s[0], ParagraphStyle("s2k", fontName="Helvetica-Bold", fontSize=8, textColor=ROXO_MEDIO, leading=10)),
            Paragraph(s[1], val),
        ])

    ts2 = Table(soc2_data, colWidths=[55*mm, 115*mm])
    ts2.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_HEADER),
        ("TEXTCOLOR",     (0,0), (-1,0), BRANCO),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [BRANCO, FUNDO_LINHA]),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(ts2)


def _ferramentas_por_tipo(tipo: str) -> list:
    base = [
        ["Gemini AI", "IA / LLM", "Priorização e análise de vulnerabilidades com IA", "Google DeepMind"],
    ]
    if tipo == "Repositório":
        return [
            ["Semgrep", "SAST", "Análise estática de código-fonte", "semgrep.dev"],
            ["Trivy", "SCA", "Análise de composição de software e dependências vulneráveis", "aquasecurity.github.io"],
        ] + base
    elif tipo in ["API", "Aplicação"]:
        return [
            ["OWASP ZAP", "DAST", "Análise dinâmica da aplicação em execução", "zaproxy.org"],
        ] + base
    return base


def _parse_markdown(texto: str, estilos) -> list:
    flowables = []
    for linha in texto.split("\n"):
        linha = linha.rstrip()
        if not linha:
            flowables.append(Spacer(1, 3))
            continue
        if linha.startswith("### "):
            flowables.append(Paragraph(linha[4:], estilos["h3"]))
        elif linha.startswith("## "):
            flowables.append(Paragraph(linha[3:], estilos["h2"]))
        elif linha.startswith("# "):
            flowables.append(Paragraph(linha[2:], estilos["secao"]))
        elif linha.startswith("- ") or linha.startswith("* "):
            txt = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", linha[2:])
            flowables.append(Paragraph(f"&nbsp;&nbsp;&nbsp;• {txt}", estilos["corpo"]))
        else:
            txt = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", linha)
            if re.match(r"^\d+\.\s", txt):
                flowables.append(Paragraph(f"&nbsp;&nbsp;{txt}", estilos["corpo"]))
            else:
                flowables.append(Paragraph(txt, estilos["corpo"]))
    return flowables


def _secao_vulnerabilidades(story, analise: str, estilos):
    if "[NIVEL:" not in analise:
        return

    story.append(Paragraph("2. Vulnerabilidades Identificadas", estilos["secao"]))
    _linha_hr(story)

    contagem = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
    blocos_count = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', analise, flags=re.DOTALL)
    j = 1
    while j < len(blocos_count) - 2:
        nivel_c = blocos_count[j].strip()
        resto_c = blocos_count[j+2]
        itens_c = [l for l in resto_c.split("\n") if l.strip().startswith("- ")]
        if nivel_c in contagem:
            contagem[nivel_c] += len(itens_c) if itens_c else 1
        j += 3

    lbl = ParagraphStyle("lbl3", fontName="Helvetica-Bold", fontSize=8, textColor=TEXTO_CLARO)
    resumo_data = [[
        Paragraph("Criticas", lbl), Paragraph("Altas", lbl),
        Paragraph("Medias", lbl), Paragraph("Baixas", lbl),
    ], [
        Paragraph(str(contagem["critico"]), ParagraphStyle("rc", fontName="Helvetica-Bold", fontSize=16, textColor=CRITICO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem["alto"]),    ParagraphStyle("ra", fontName="Helvetica-Bold", fontSize=16, textColor=ALTO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem["medio"]),   ParagraphStyle("rm", fontName="Helvetica-Bold", fontSize=16, textColor=MEDIO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem["baixo"]),   ParagraphStyle("rb", fontName="Helvetica-Bold", fontSize=16, textColor=BAIXO, leading=19, alignment=TA_CENTER)),
    ]]
    tr = Table(resumo_data, colWidths=[42*mm]*4)
    tr.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_LINHA),
        ("BACKGROUND",    (0,1), (-1,1), BRANCO),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LINEABOVE",     (0,1), (0,1), 3, CRITICO),
        ("LINEABOVE",     (1,1), (1,1), 3, ALTO),
        ("LINEABOVE",     (2,1), (2,1), 3, MEDIO),
        ("LINEABOVE",     (3,1), (3,1), 3, BAIXO),
    ]))
    story.append(tr)
    story.append(Spacer(1, 10))

    blocos = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', analise, flags=re.DOTALL)
    i = 1
    while i < len(blocos) - 2:
        nivel  = blocos[i].strip()
        titulo = blocos[i+1].strip()
        resto  = blocos[i+2]
        itens  = [l[2:].strip() for l in resto.split("\n") if l.strip().startswith("- ")]

        cor   = {"critico": CRITICO, "alto": ALTO, "medio": MEDIO, "baixo": BAIXO}.get(nivel, TEXTO_CLARO)
        badge = {"critico": "CRITICO", "alto": "ALTO", "medio": "MEDIO", "baixo": "BAIXO"}.get(nivel, nivel.upper())

        tt = ParagraphStyle("ct", fontName="Helvetica-Bold", fontSize=9, textColor=cor, leading=12)
        bt = ParagraphStyle("cb", fontName="Helvetica-Bold", fontSize=8, textColor=BRANCO, alignment=TA_CENTER, leading=10)
        it = ParagraphStyle("ci", fontName="Helvetica", fontSize=9, textColor=TEXTO_MEDIO, leading=13)

        linhas = [[Paragraph(titulo, tt), Paragraph(badge, bt)]]
        for item in itens:
            linhas.append([Paragraph(f"• {item}", it), Paragraph("", it)])

        t = Table(linhas, colWidths=[148*mm, 22*mm])
        ts = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  FUNDO_CARD),
            ("BACKGROUND",    (1,0), (1,0),   cor),
            ("BACKGROUND",    (0,1), (-1,-1), BRANCO),
            ("LINEBEFORE",    (0,0), (0,-1),  3, cor),
            ("BOX",           (0,0), (-1,-1), 0.3, BORDA),
            ("LINEBELOW",     (0,0), (-1,0),  0.3, BORDA),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ])
        t.setStyle(ts)
        story.append(t)
        story.append(Spacer(1, 5))
        i += 3


def _secao_relatorio(story, relatorio: str, estilos):
    if not relatorio.strip():
        return
    story.append(Paragraph("3. Relatório Executivo", estilos["secao"]))
    _linha_hr(story)
    for f in _parse_markdown(relatorio, estilos):
        story.append(f)


def _secao_declaracao(story, nome_usuario: str, estilos):
    story.append(PageBreak())
    story.append(Paragraph("4. Declaração de Conformidade", estilos["secao"]))
    _linha_hr(story)

    lbl = ParagraphStyle("lbl4", fontName="Helvetica-Bold", fontSize=8, textColor=TEXTO_CLARO)
    val = ParagraphStyle("val4", fontName="Helvetica", fontSize=9, textColor=TEXTO_MEDIO, leading=12)

    story.append(Paragraph(
        "Este relatório foi gerado pela plataforma ASPM e documenta os resultados da analise "
        "de seguranca realizada sobre o ativo descrito na secao 1. As analises foram conduzidas "
        "com ferramentas reconhecidas pelo mercado e mapeadas para os principais frameworks de "
        "seguranca (ISO 27001, SOC2 Type II, CIS Benchmark).",
        val
    ))
    story.append(Spacer(1, 8))

    iso_controles = [
        ["A.8.8",  "Gestão de Vulnerabilidades Tecnicas", "Cobertura por SAST, DAST e SCA"],
        ["A.8.25", "Ciclo de Vida de Desenvolvimento Seguro", "Pipeline CI/CD com verificações de segurança"],
        ["A.8.29", "Testes de Segurança no Desenvolvimento", "Testes automatizados a cada commit"],
        ["A.5.23", "Segurança no Uso de Serviços em Nuvem", "Monitoramento continuo de ativos"],
        ["A.8.16", "Monitoramento de Atividades", "Alertas e histórico de risk score"],
    ]

    story.append(Paragraph("Controles ISO 27001 Cobertos", estilos["label"]))
    story.append(Spacer(1, 4))

    iso_data = [[
        Paragraph("<b>Controle</b>", lbl),
        Paragraph("<b>Descricao</b>", lbl),
        Paragraph("<b>Evidencia na Plataforma</b>", lbl),
    ]]
    for row in iso_controles:
        iso_data.append([
            Paragraph(row[0], ParagraphStyle("isk", fontName="Helvetica-Bold", fontSize=8, textColor=ROXO_MEDIO, leading=10)),
            Paragraph(row[1], val),
            Paragraph(row[2], val),
        ])

    ti = Table(iso_data, colWidths=[20*mm, 75*mm, 75*mm])
    ti.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_HEADER),
        ("TEXTCOLOR",     (0,0), (-1,0), BRANCO),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [BRANCO, FUNDO_LINHA]),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(ti)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Responsável pela Análise", estilos["label"]))
    story.append(Spacer(1, 4))
    assin_data = [
        [Paragraph("Nome", lbl), Paragraph("Data", lbl), Paragraph("Plataforma", lbl)],
        [Paragraph(nome_usuario, val),
         Paragraph(datetime.now().strftime("%d/%m/%Y"), val),
         Paragraph("ASPM Platform", val)],
    ]
    ta = Table(assin_data, colWidths=[60*mm, 50*mm, 60*mm])
    ta.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), FUNDO_LINHA),
        ("BACKGROUND",    (0,1), (-1,1), BRANCO),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(ta)


def _rodape(canvas_obj, doc):
    W, H = A4
    canvas_obj.saveState()
    canvas_obj.setFillColor(FUNDO_LINHA)
    canvas_obj.rect(0, 0, W, 16*mm, fill=1, stroke=0)
    canvas_obj.setFillColor(ROXO_MEDIO)
    canvas_obj.rect(0, 16*mm, W, 0.5*mm, fill=1, stroke=0)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(TEXTO_CLARO)
    canvas_obj.drawString(20*mm, 6*mm, "ASPM Platform — Relatório Confidencial | ISO 27001 | SOC2 Type II")
    canvas_obj.drawRightString(W - 20*mm, 6*mm,
        f"Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')}  |  Página {doc.page}")
    canvas_obj.restoreState()


def gerar_pdf_relatorio(ativo: dict, analise_completa: str, nome_usuario: str = "Analista ASPM") -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=22*mm)

    estilos = _estilos()
    story   = []

    _bloco_capa(story, ativo, nome_usuario, estilos)

    sast_dast = sca = relatorio = ""
    if "---VULNS_SAST_DAST---" in analise_completa:
        sast_dast = analise_completa.split("---VULNS_SAST_DAST---")[1].split("---VULNS_SCA---")[0].strip()
        sca       = analise_completa.split("---VULNS_SCA---")[1].split("---RELATORIO---")[0].strip()
    elif "---VULNS---" in analise_completa:
        bloco = analise_completa.split("---VULNS---")[1].split("---RELATORIO---")[0].strip()
        if "### Trivy" in bloco:
            p = bloco.split("### Trivy", 1)
            sast_dast, sca = p[0].strip(), "### Trivy\n\n" + p[1].strip()
        else:
            sast_dast = bloco
    else:
        sast_dast = analise_completa

    if "---RELATORIO---" in analise_completa:
        relatorio = analise_completa.split("---RELATORIO---")[1].strip()

    story.append(PageBreak())
    _secao_vulnerabilidades(story, sast_dast + "\n" + sca, estilos)

    if relatorio:
        story.append(PageBreak())
        _secao_relatorio(story, relatorio, estilos)

    _secao_declaracao(story, nome_usuario, estilos)

    doc.build(story, onFirstPage=_rodape, onLaterPages=_rodape)
    buffer.seek(0)
    return buffer.read()