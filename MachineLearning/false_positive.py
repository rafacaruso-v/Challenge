import re
import math
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier

_MODELO = None

LIMIAR_DESCARTE_AUTOMATICO = 0.95
LIMIAR_ANOTACAO           = 0.40

PALAVRAS_INDICAM_TESTE = [
    "test", "tests", "example", "examples", "mock", "mocks", "dummy", "fake",
    "sample", "demo", "placeholder", "lorem", "foo", "bar", "xxx",
    "changeme", "todo",
]

PALAVRAS_INDICAM_REAL = [
    "senha", "password", "secret", "token", "credential", "credencial",
    "cliente", "prod", "production",
    "authorization",
]

CAMINHOS_INDICAM_TESTE = [
    "test", "tests", "mock", "mocks", "docs", "doc",
    "example", "examples", "readme", "fixtures", "spec",
]

CAMINHOS_INDICAM_REAL = [
    "src", "config", "api", "auth", "database", "db",
    "services", "controllers", "models", "routes",
]

SCANNER_TIPOS = ["SAST", "DAST", "SCA", "CSPM", "IAC"]

def _entropia_shannon(texto: str) -> float:
    if not texto:
        return 0.0
    freq = {}
    for c in texto:
        freq[c] = freq.get(c, 0) + 1
    tamanho = len(texto)
    entropia = 0.0
    for count in freq.values():
        p = count / tamanho
        entropia -= p * math.log2(p)
    return entropia


def _extrair_token_valor(texto: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_\-/+=]{8,}", texto)
    if not tokens:
        return texto
    return max(tokens, key=len)


def _texto_para_entropia(texto: str) -> str:
    if ":" in texto:
        return texto.split(":", 1)[1].strip()
    return texto


def _palavra_presente(texto_normalizado: str, palavra: str) -> bool:
    return re.search(rf"\b{re.escape(palavra)}\b", texto_normalizado) is not None


def _contar_ocorrencias(texto: str, lista_palavras: list) -> int:
    texto_norm = re.sub(r"[\\/_\-\.]", " ", texto.lower())
    return sum(1 for palavra in lista_palavras if _palavra_presente(texto_norm, palavra))


def _caminho_contem_segmento(caminho: str, lista_segmentos: list) -> bool:
    caminho_norm = re.sub(r"[\\/_\-\.\s]", " ", caminho.lower())
    return any(_palavra_presente(caminho_norm, seg) for seg in lista_segmentos)


def _extrair_features(texto: str, caminho: str = "", tipo_scanner: str = "SAST") -> list:
    texto = texto or ""
    caminho = caminho or ""

    texto_entropia = _texto_para_entropia(texto)
    token_valor = _extrair_token_valor(texto_entropia)
    entropia = _entropia_shannon(token_valor)
    tamanho_token = len(token_valor)
    tamanho_texto = len(texto)

    qtd_palavras_teste = _contar_ocorrencias(texto + " " + caminho, PALAVRAS_INDICAM_TESTE)
    qtd_palavras_real  = _contar_ocorrencias(texto + " " + caminho, PALAVRAS_INDICAM_REAL)

    caminho_indica_teste = 1 if _caminho_contem_segmento(caminho, CAMINHOS_INDICAM_TESTE) else 0
    caminho_indica_real  = 1 if _caminho_contem_segmento(caminho, CAMINHOS_INDICAM_REAL) else 0

    onehot_scanner = [1 if tipo_scanner == t else 0 for t in SCANNER_TIPOS]

    return [
        entropia,
        tamanho_token,
        tamanho_texto,
        qtd_palavras_teste,
        qtd_palavras_real,
        caminho_indica_teste,
        caminho_indica_real,
        *onehot_scanner,
    ]


def _gerar_dataset_sintetico(n=4000, seed=42):
    rng = np.random.default_rng(seed)
    X = []
    y = []

    for _ in range(n):
        e_falso_positivo = rng.choice([0, 1], p=[0.45, 0.55])
        tipo_scanner = rng.choice(SCANNER_TIPOS)

        if e_falso_positivo:
            entropia = rng.uniform(1.5, 3.2)
            tamanho_token = int(rng.integers(8, 20))
            tamanho_texto = int(rng.integers(20, 80))
            qtd_palavras_teste = int(rng.integers(1, 4))
            qtd_palavras_real = 0
            caminho_indica_teste = rng.choice([0, 1], p=[0.3, 0.7])
            caminho_indica_real = 0
        else:
            entropia = rng.uniform(3.5, 5.5)
            tamanho_token = int(rng.integers(16, 64))
            tamanho_texto = int(rng.integers(30, 150))
            qtd_palavras_teste = 0
            qtd_palavras_real = int(rng.integers(1, 3))
            caminho_indica_teste = 0
            caminho_indica_real = rng.choice([0, 1], p=[0.4, 0.6])

        onehot_scanner = [1 if tipo_scanner == t else 0 for t in SCANNER_TIPOS]

        ruido = rng.normal(0, 0.15)
        features = [
            max(0, entropia + ruido),
            tamanho_token,
            tamanho_texto,
            qtd_palavras_teste,
            qtd_palavras_real,
            caminho_indica_teste,
            caminho_indica_real,
            *onehot_scanner,
        ]

        X.append(features)
        y.append(e_falso_positivo)

    return np.array(X), np.array(y)


def _obter_modelo():
    global _MODELO
    if _MODELO is None:
        X, y = _gerar_dataset_sintetico()
        _MODELO = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
        _MODELO.fit(X, y)
    return _MODELO


def calcular_probabilidade_fp(texto: str, caminho: str = "", tipo_scanner: str = "SAST") -> float:
    modelo = _obter_modelo()
    features = _extrair_features(texto, caminho, tipo_scanner)
    entrada = np.array([features])
    probabilidade = modelo.predict_proba(entrada)[0]
    classes = list(modelo.classes_)
    idx_fp = classes.index(1) if 1 in classes else 0
    return float(probabilidade[idx_fp])


def filtrar_falsos_positivos(findings: list) -> tuple:

    mantidos = []
    descartados = []

    for finding in findings:
        prob_fp = calcular_probabilidade_fp(
            texto=finding.get("texto", ""),
            caminho=finding.get("caminho", ""),
            tipo_scanner=finding.get("tipo_scanner", "SAST"),
        )

        if prob_fp >= LIMIAR_DESCARTE_AUTOMATICO:
            finding_descartado = dict(finding)
            finding_descartado["fp_probabilidade"] = round(prob_fp, 3)
            descartados.append(finding_descartado)
            continue

        finding_mantido = dict(finding)
        finding_mantido["fp_probabilidade"] = round(prob_fp, 3)
        mantidos.append(finding_mantido)

    return mantidos, descartados

def reduzir_falsos_positivos_sast(resultado_sast_raw: str):
    try:
        achados = json.loads(resultado_sast_raw)
        if not isinstance(achados, list) or not achados:
            return resultado_sast_raw, []
    except (json.JSONDecodeError, TypeError):
        return resultado_sast_raw, []

    findings_normalizados = []
    for item in achados:
        texto = f"{item.get('check_id', '')}: {item.get('message', '')}"
        caminho = item.get("path", "")
        findings_normalizados.append({
            "texto": texto,
            "caminho": caminho,
            "tipo_scanner": "SAST",
            "_original": item,
        })

    mantidos, descartados = filtrar_falsos_positivos(findings_normalizados)

    achados_filtrados = [f["_original"] for f in mantidos]
    descartados_limpos = [
        {
            "texto": d["texto"],
            "caminho": d["caminho"],
            "tipo_scanner": d["tipo_scanner"],
            "fp_probabilidade": d["fp_probabilidade"],
        }
        for d in descartados
    ]
    return json.dumps(achados_filtrados, ensure_ascii=False), descartados_limpos


def reduzir_falsos_positivos_sca(resultado_sca_raw: str):
    try:
        achados = json.loads(resultado_sca_raw)
        if not isinstance(achados, list) or not achados:
            return resultado_sca_raw, []
    except (json.JSONDecodeError, TypeError):
        return resultado_sca_raw, []

    findings_normalizados = []
    for item in achados:
        texto = f"{item.get('cve', '')}: {item.get('title', '')} em {item.get('package', '')}"
        caminho = item.get("file", "")
        findings_normalizados.append({
            "texto": texto,
            "caminho": caminho,
            "tipo_scanner": "SCA",
            "_original": item,
        })

    mantidos, descartados = filtrar_falsos_positivos(findings_normalizados)

    achados_filtrados = [f["_original"] for f in mantidos]
    descartados_limpos = [
        {
            "texto": d["texto"],
            "caminho": d["caminho"],
            "tipo_scanner": d["tipo_scanner"],
            "fp_probabilidade": d["fp_probabilidade"],
        }
        for d in descartados
    ]
    return json.dumps(achados_filtrados, ensure_ascii=False), descartados_limpos


def reduzir_falsos_positivos_dast(resultado_dast_raw: str):
    try:
        achados = json.loads(resultado_dast_raw)
        if not isinstance(achados, list) or not achados:
            return resultado_dast_raw, []
    except (json.JSONDecodeError, TypeError):
        return resultado_dast_raw, []

    findings_normalizados = []
    for item in achados:
        texto = f"{item.get('name', '')}: {item.get('description', '')}"
        endpoints = item.get("endpoints", [])
        caminho = endpoints[0] if endpoints else ""
        findings_normalizados.append({
            "texto": texto,
            "caminho": caminho,
            "tipo_scanner": "DAST",
            "_original": item,
        })

    mantidos, descartados = filtrar_falsos_positivos(findings_normalizados)

    achados_filtrados = [f["_original"] for f in mantidos]
    descartados_limpos = [
        {
            "texto": d["texto"],
            "caminho": d["caminho"],
            "tipo_scanner": d["tipo_scanner"],
            "fp_probabilidade": d["fp_probabilidade"],
        }
        for d in descartados
    ]
    return json.dumps(achados_filtrados, ensure_ascii=False), descartados_limpos

def reduzir_falsos_positivos_cspm(achados: list):
    """
    Filtra achados de CSPM (lista bruta vinda de run_cspm_scan, ANTES de
    formatar_achados_cspm) usando o mesmo modelo de ML dos outros scanners.
    """
    if not achados:
        return achados, []

    findings_normalizados = []
    for item in achados:
        recurso = item.get("recurso", "")
        descricao = item.get("descricao", "")
        texto = f"{recurso}: {descricao}"
        findings_normalizados.append({
            "texto": texto,
            "caminho": recurso,
            "tipo_scanner": "CSPM",
            "_original": item,
        })

    mantidos, descartados = filtrar_falsos_positivos(findings_normalizados)

    achados_filtrados = [f["_original"] for f in mantidos]
    descartados_limpos = [
        {
            "texto": d["texto"],
            "caminho": d["caminho"],
            "tipo_scanner": d["tipo_scanner"],
            "fp_probabilidade": d["fp_probabilidade"],
        }
        for d in descartados
    ]
    return achados_filtrados, descartados_limpos


def reduzir_falsos_positivos_iac(achados: list):
    if not achados:
        return achados, []

    findings_normalizados = []
    for item in achados:
        recurso = item.get("recurso", "")
        descricao = item.get("descricao", "")
        contexto = item.get("contexto_ia") or {}
        caminho = contexto.get("file_path", recurso)
        texto = f"{recurso}: {descricao}"
        findings_normalizados.append({
            "texto": texto,
            "caminho": caminho,
            "tipo_scanner": "IAC",
            "_original": item,
        })

    mantidos, descartados = filtrar_falsos_positivos(findings_normalizados)

    achados_filtrados = [f["_original"] for f in mantidos]
    descartados_limpos = [
        {
            "texto": d["texto"],
            "caminho": d["caminho"],
            "tipo_scanner": d["tipo_scanner"],
            "fp_probabilidade": d["fp_probabilidade"],
        }
        for d in descartados
    ]
    return achados_filtrados, descartados_limpos