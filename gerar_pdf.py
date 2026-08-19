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
from Compliance.avaliador import avaliar_plataforma

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

CONFORME              = colors.HexColor("#15803d")
PARCIALMENTE_CONFORME = colors.HexColor("#d97706")
NAO_CONFORME          = colors.HexColor("#dc2626")
NAO_AVALIADO          = colors.HexColor("#6b7280")


def _cor_criticidade(crit: str):
    return {"Critica": CRITICO, "Alta": ALTO, "Média": MEDIO, "Baixa": BAIXO}.get(crit, TEXTO_CLARO)


def _extrair_nomes_vulnerabilidades(texto: str) -> dict:
    nomes = {"critico": [], "alto": [], "medio": [], "baixo": []}
    if not texto or "[NIVEL:" not in texto:
        return nomes

    blocos = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', texto, flags=re.DOTALL)
    j = 1
    while j < len(blocos) - 1:
        nivel_atual = blocos[j].strip()
        resto = blocos[j + 2] if (j + 2) < len(blocos) else ""
        itens = [l[2:].strip() for l in resto.split("\n") if l.strip().startswith("- ")]
        for item in itens:
            nome = item.split(":", 1)[0].strip()
            if nivel_atual in nomes and nome and nome not in nomes[nivel_atual]:
                nomes[nivel_atual].append(nome)
        j += 3

    return nomes


def _cor_status_compliance(status: str):
    return {
        "Conforme": CONFORME,
        "Parcialmente Conforme": PARCIALMENTE_CONFORME,
        "Não Conforme": NAO_CONFORME,
        "Não Aplicável": NAO_AVALIADO,
        "Não Avaliado": NAO_AVALIADO,
    }.get(status, NAO_AVALIADO)


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


def _bloco_capa(story, ativo, nome_usuario, estilos, vulnerabilidades_texto: str = ""):
    W = 170 * mm

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
    cst = ParagraphStyle("cst", fontName="Helvetica", fontSize=9, textColor=TEXTO_ESCURO, alignment=TA_CENTER)
    sst = ParagraphStyle("sst", fontName="Helvetica", fontSize=9, textColor=TEXTO_ESCURO, alignment=TA_CENTER)

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
    story.append(Spacer(1, 14))

    story.append(Paragraph(
        f'<b>URL / Caminho:</b> {ativo.get("url", "-")}',
        ParagraphStyle("url", fontName="Helvetica", fontSize=8, textColor=TEXTO_CLARO, leading=11)
    ))
    _linha_hr(story)

    story.append(Paragraph("1. Escopo e Metodologia", estilos["secao"]))
    _linha_hr(story)

    escopo_data = [
        [Paragraph("Periodo da Análise", lbl), Paragraph("Responsável", lbl),
         Paragraph("Frameworks de Referência", lbl)],
        [Paragraph(ativo.get("ultima_analise", datetime.now().strftime("%d/%m/%Y %H:%M")), val),
         Paragraph(nome_usuario, val),
         Paragraph("ISO 27001 | SOC2 Type II | ", val)],
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
    story.append(Spacer(1, 16))

    story.append(Paragraph("Ferramentas Utilizadas", estilos["label"]))
    story.append(Spacer(1, 4))

    ferramentas = _ferramentas_por_tipo(ativo["tipo"])
    fer_data = [[
        Paragraph("<b>Ferramenta</b>", lbl),
        Paragraph("<b>Categoria</b>", lbl),
        Paragraph("<b>Descricão</b>", lbl),
        Paragraph("<b>Referência</b>", lbl),
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
    story.append(Spacer(1, 16))

    nomes = _extrair_nomes_vulnerabilidades(vulnerabilidades_texto)
    if any(nomes.values()):
        story.append(Paragraph("Resumo de Vulnerabilidades Identificadas", estilos["label"]))
        story.append(Spacer(1, 4))

        labels_niveis = {
            "critico": "Criticas",
            "alto":    "Altas",
            "medio":   "Medias",
            "baixo":   "Baixas",
        }
        estilo_label_nivel = ParagraphStyle("rn_nivel", fontName="Helvetica-Bold", fontSize=8, textColor=ROXO_MEDIO, leading=11, alignment=TA_CENTER)
        estilo_valor_nivel = ParagraphStyle("rv_nivel", fontName="Helvetica", fontSize=8.5, textColor=TEXTO_MEDIO, leading=12)
        linhas_resumo = []
        for nivel in ["critico", "alto", "medio", "baixo"]:
            if nomes[nivel]:
                linhas_resumo.append([
                    Paragraph(labels_niveis[nivel], estilo_label_nivel),
                    Paragraph(", ".join(nomes[nivel]), estilo_valor_nivel),
                ])

        tr_resumo = Table(linhas_resumo, colWidths=[25*mm, 145*mm])
        tr_resumo.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), FUNDO_LINHA),
            ("BOX",           (0,0), (-1,-1), 0.5, BORDA),
            ("GRID",          (0,0), (-1,-1), 0.3, BORDA),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(tr_resumo)
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "<i>Descrição detalhada de cada item disponível na seção 2 deste relatório.</i>",
            ParagraphStyle("nota_resumo", fontName="Helvetica-Oblique", fontSize=7, textColor=TEXTO_CLARO, leading=9)
        ))
    else:
        story.append(Paragraph("✅ Nenhuma vulnerabilidade identificada nesta análise.", estilos["corpo"]))


def _ferramentas_por_tipo(tipo: str) -> list:
    base = [
        ["Gemini AI", "IA / LLM", "Priorização e análise de vulnerabilidades com IA", "Google DeepMind"],
    ]
    if tipo == "Repositório":
        return [
            ["Semgrep", "SAST", "Análise estática de código-fonte", "semgrep.dev"],
            ["Trivy", "SCA", "Análise de composição de software e dependências vulneráveis", "aquasecurity.github.io"],
            ["Checkov", "IaC", "Análise de segurança de Infraestrutura como Código (Terraform/CloudFormation)", "checkov.io"],
            ["Gitleaks", "Secrets", "Detecção de credenciais e segredos expostos no código-fonte", "gitleaks.io"],
            ["DLP Scanner", "DLP", "Detecção de dados sensíveis de terceiros (CPF, CNPJ, cartão, e-mail)", "ASPM Platform"],
        ] + base
    elif tipo in ["API", "Aplicação"]:
        return [
            ["OWASP ZAP", "DAST", "Análise dinâmica da aplicação em execução", "zaproxy.org"],
        ] + base
    elif tipo == "Cloud":
        return [
            ["CSPM (ASPM Platform)", "CSPM", "Análise de postura de segurança da conta AWS (S3/IAM/EC2/Conta)", "ASPM Platform"],
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


def _contar_niveis(texto: str) -> dict:
    contagem = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
    if not texto or "[NIVEL:" not in texto:
        return contagem

    blocos = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', texto, flags=re.DOTALL)
    j = 1
    while j < len(blocos) - 2:
        nivel = blocos[j].strip()
        resto = blocos[j+2]
        itens = [l for l in resto.split("\n") if l.strip().startswith("- ")]
        if nivel in contagem:
            contagem[nivel] += len(itens) if itens else 1
        j += 3

    return contagem


def _render_itens_por_nivel(story, texto: str):
    """Renderiza os cards de achados de UM bloco/categoria específica."""
    blocos = re.split(r'\[NIVEL:(\w+)\](.*?)\[/NIVEL\]', texto, flags=re.DOTALL)
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


def _secao_vulnerabilidades(story, secoes: dict, estilos):
    """
    `secoes` é um dict ORDENADO {titulo_da_categoria: texto_bruto_do_bloco},
    ex: {"SAST / Análise Estática": sast_dast, "SCA / Dependências": sca, ...}.

    Diferente da versão anterior (que recebia um único blob de texto já
    misturando SCA+CSPM+IaC+Secrets+DLP), aqui cada categoria é renderizada
    em sua própria subseção, com título identificando a origem do achado —
    evita que uma credencial exposta (Secrets) apareça no relatório como se
    fosse um achado de SCA, por exemplo.
    """
    secoes_com_achados = {
        titulo: texto for titulo, texto in secoes.items()
        if texto and "[NIVEL:" in texto
    }
    if not secoes_com_achados:
        return

    story.append(Paragraph("2. Vulnerabilidades Identificadas", estilos["secao"]))
    _linha_hr(story)

    contagem_total = {"critico": 0, "alto": 0, "medio": 0, "baixo": 0}
    for texto in secoes_com_achados.values():
        c = _contar_niveis(texto)
        for nivel in contagem_total:
            contagem_total[nivel] += c[nivel]

    lbl = ParagraphStyle("lbl3", fontName="Helvetica-Bold", fontSize=8, textColor=TEXTO_CLARO)
    resumo_data = [[
        Paragraph("Criticas", lbl), Paragraph("Altas", lbl),
        Paragraph("Medias", lbl), Paragraph("Baixas", lbl),
    ], [
        Paragraph(str(contagem_total["critico"]), ParagraphStyle("rc", fontName="Helvetica-Bold", fontSize=16, textColor=CRITICO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem_total["alto"]),    ParagraphStyle("ra", fontName="Helvetica-Bold", fontSize=16, textColor=ALTO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem_total["medio"]),   ParagraphStyle("rm", fontName="Helvetica-Bold", fontSize=16, textColor=MEDIO, leading=19, alignment=TA_CENTER)),
        Paragraph(str(contagem_total["baixo"]),   ParagraphStyle("rb", fontName="Helvetica-Bold", fontSize=16, textColor=BAIXO, leading=19, alignment=TA_CENTER)),
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

    for titulo_categoria, texto in secoes_com_achados.items():
        story.append(Paragraph(titulo_categoria, estilos["h3"]))
        _render_itens_por_nivel(story, texto)


def _secao_relatorio(story, relatorio: str, estilos):
    if not relatorio.strip():
        return
    story.append(Paragraph("3. Relatório Executivo", estilos["secao"]))
    _linha_hr(story)
    for f in _parse_markdown(relatorio, estilos):
        story.append(f)


def _secao_declaracao(story, nome_usuario: str, estilos, compliance: dict):
    story.append(PageBreak())
    story.append(Paragraph("4. Declaração de Conformidade", estilos["secao"]))
    _linha_hr(story)

    lbl = ParagraphStyle("lbl4", fontName="Helvetica-Bold", fontSize=8, textColor=TEXTO_CLARO)
    val = ParagraphStyle("val4", fontName="Helvetica", fontSize=9, textColor=TEXTO_MEDIO, leading=12)

    story.append(Paragraph(
        "Este relatório foi gerado pela plataforma ASPM e documenta os resultados da análise "
    "de segurança realizada sobre o ativo descrito na seção 1. Os status de conformidade "
    "abaixo avaliam a postura de segurança da plataforma ASPM como um todo — incluindo "
    "autenticação, cobertura de scanners, auditoria e avaliação de riscos — e são "
    "calculados automaticamente a partir dos dados reais registrados na plataforma, "
    "não sendo uma característica exclusiva deste ativo específico.",
        val
    ))
    story.append(Spacer(1, 20))
    gv = compliance["mitigacao_vulnerabilidades"]
    al = compliance["acesso_logico"]
    rt = compliance["rastreabilidade"]
    ar = compliance["avaliacao_riscos"]

    story.append(Paragraph("Critérios SOC2 Avaliados (Trust Service Criteria)", estilos["label"]))
    story.append(Spacer(1, 4))

    soc2 = [
        ["CC6 — Logical Access", "Controles de acesso lógico e físico da plataforma (MFA, RBAC)", al["status"], al["detalhe"]],
        ["CC7 — Vulnerability Mitigation", "Descoberta, priorização e monitoramento de vulnerabilidades (SAST/DAST/SCA)", gv["status"], gv["detalhe"]],
        ["CC6 & CC8 — Traceability", "Audit trails e alertas de incidentes de segurança", rt["status"], rt["detalhe"]],
        ["CC3 — Risk Assessment", "Identificação, análise e classificação de riscos dos ativos", ar["status"], ar["detalhe"]],
    ]
    soc2_data = [[Paragraph("<b>Critério</b>", lbl), Paragraph("<b>Descrição</b>", lbl),
                  Paragraph("<b>Status</b>", lbl), Paragraph("<b>Evidência</b>", lbl)]]
    for s in soc2:
        cor_status = _cor_status_compliance(s[2])
        soc2_data.append([
            Paragraph(s[0], ParagraphStyle("s2k", fontName="Helvetica-Bold", fontSize=8, textColor=ROXO_MEDIO, leading=10)),
            Paragraph(s[1], val),
            Paragraph(s[2], ParagraphStyle("s2st", fontName="Helvetica-Bold", fontSize=8, textColor=cor_status, leading=10)),
            Paragraph(s[3], ParagraphStyle("s2ev", fontName="Helvetica", fontSize=7.5, textColor=TEXTO_CLARO, leading=9)),
        ])

    ts2 = Table(soc2_data, colWidths=[38*mm, 45*mm, 27*mm, 60*mm])
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
    story.append(Spacer(1, 12))

    iso_controles = [
        ["A.5.15", "Controle de Acesso", al["status"], al["detalhe"]],
        ["A.8.8",  "Gestão de Vulnerabilidades Tecnicas", gv["status"], gv["detalhe"]],
        ["A.8.15", "Registro de Eventos (Logging) e Auditoria", rt["status"], rt["detalhe"]],
        ["Cláusula 6.1.2", "Avaliação de Riscos de Segurança da Informação", ar["status"], ar["detalhe"]],
    ]

    story.append(Paragraph("Controles ISO 27001 Cobertos", estilos["label"]))
    story.append(Spacer(1, 4))

    iso_data = [[
        Paragraph("<b>Controle</b>", lbl),
        Paragraph("<b>Descrição</b>", lbl),
        Paragraph("<b>Status</b>", lbl),
        Paragraph("<b>Evidência na Plataforma</b>", lbl),
    ]]
    for row in iso_controles:
        cor_status = _cor_status_compliance(row[2])
        iso_data.append([
            Paragraph(row[0], ParagraphStyle("isk", fontName="Helvetica-Bold", fontSize=8, textColor=ROXO_MEDIO, leading=10)),
            Paragraph(row[1], val),
            Paragraph(row[2], ParagraphStyle("isost", fontName="Helvetica-Bold", fontSize=8, textColor=cor_status, leading=10)),
            Paragraph(row[3], ParagraphStyle("isoev", fontName="Helvetica", fontSize=7.5, textColor=TEXTO_CLARO, leading=9)),
        ])

    ti = Table(iso_data, colWidths=[20*mm, 45*mm, 27*mm, 78*mm])
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
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<i>Nota: Os critérios SOC2 e ISO 27001 acima avaliam a postura de compliance da "
        "plataforma ASPM como um todo (autenticação, cobertura de scanners, auditoria e "
        "avaliação de riscos), não uma característica exclusiva deste ativo específico.</i>",
        ParagraphStyle("nota_plataforma", fontName="Helvetica-Oblique", fontSize=7, textColor=TEXTO_CLARO, leading=9)
    ))


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


def _extrair_blocos(analise_completa: str) -> dict:
    """
    Extrai cada bloco (SAST_DAST, SCA, CSPM, IAC, SECRETS, DLP, FP, RELATORIO)
    de forma independente, buscando cada marcador diretamente no texto
    completo — ao invés de encadear splits sequenciais, o que fazia blocos
    faltantes "vazarem" conteúdo de uma categoria para outra.

    Suporta tanto o formato atual (com todos os 8 marcadores) quanto o
    formato legado (---VULNS--- único, sem separação por categoria).
    """
    marcadores_em_ordem = [
        "---VULNS_SAST_DAST---", "---VULNS_SCA---", "---VULNS_CSPM---",
        "---VULNS_IAC---", "---VULNS_SECRETS---", "---VULNS_DLP---",
        "---VULNS_FP---", "---RELATORIO---",
    ]

    blocos = {
        "sast_dast": "", "sca": "", "cspm": "", "iac": "",
        "secrets": "", "dlp": "", "fp": "", "relatorio": "",
    }
    chaves_em_ordem = ["sast_dast", "sca", "cspm", "iac", "secrets", "dlp", "fp", "relatorio"]

    if "---VULNS_SAST_DAST---" in analise_completa:
        for i, marcador in enumerate(marcadores_em_ordem):
            if marcador not in analise_completa:
                continue
            inicio = analise_completa.split(marcador, 1)[1]
            fim_encontrado = None
            for prox_marcador in marcadores_em_ordem[i+1:]:
                if prox_marcador in inicio:
                    fim_encontrado = inicio.split(prox_marcador, 1)[0]
                    break
            blocos[chaves_em_ordem[i]] = (fim_encontrado if fim_encontrado is not None else inicio).strip()
        return blocos

    if "---VULNS---" in analise_completa:
        bloco = analise_completa.split("---VULNS---")[1].split("---RELATORIO---")[0].strip()
        if "### Trivy" in bloco:
            p = bloco.split("### Trivy", 1)
            blocos["sast_dast"], blocos["sca"] = p[0].strip(), "### Trivy\n\n" + p[1].strip()
        else:
            blocos["sast_dast"] = bloco
    else:
        blocos["sast_dast"] = analise_completa

    if "---RELATORIO---" in analise_completa:
        blocos["relatorio"] = analise_completa.split("---RELATORIO---")[1].strip()

    return blocos


def gerar_pdf_relatorio(ativo: dict, analise_completa: str, nome_usuario: str = "Analista ASPM") -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=22*mm)

    estilos = _estilos()
    story   = []

    blocos = _extrair_blocos(analise_completa)

    secoes_vulnerabilidades = {
        "2.1 SAST / DAST (Código-Fonte e Dinâmica)": blocos["sast_dast"],
        "2.2 SCA (Dependências de Software)": blocos["sca"],
        "2.3 CSPM (Postura de Nuvem)": blocos["cspm"],
        "2.4 IaC (Infraestrutura como Código)": blocos["iac"],
        "2.5 Secrets (Credenciais Expostas)": blocos["secrets"],
        "2.6 DLP (Dados Sensíveis de Terceiros)": blocos["dlp"],
    }

    texto_combinado_para_capa = "\n".join(
        texto for texto in secoes_vulnerabilidades.values() if texto
    )

    compliance = avaliar_plataforma(ativo.get("usuario_id"))

    _bloco_capa(story, ativo, nome_usuario, estilos, texto_combinado_para_capa)

    story.append(PageBreak())
    _secao_vulnerabilidades(story, secoes_vulnerabilidades, estilos)

    if blocos["relatorio"]:
        story.append(PageBreak())
        _secao_relatorio(story, blocos["relatorio"], estilos)

    _secao_declaracao(story, nome_usuario, estilos, compliance)

    doc.build(story, onFirstPage=_rodape, onLaterPages=_rodape)
    buffer.seek(0)
    return buffer.read()