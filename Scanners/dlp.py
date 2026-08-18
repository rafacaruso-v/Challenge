"""
Scanner de DLP (Data Loss Prevention) — detecta dados sensíveis de
pessoas físicas (PII) potencialmente vazados em código-fonte, configs,
fixtures de teste, etc.

Princípios de mercado seguidos aqui (mesma lógica de ferramentas como
AWS Macie, Google DLP API, Microsoft Purview):

1. VALIDAÇÃO MATEMÁTICA, NÃO SÓ REGEX — um regex que casa "11 dígitos"
   pega qualquer número de telefone, protocolo, ou ID de pedido. Só reporta
   como achado real depois de validar o dígito verificador (CPF/CNPJ) ou o
   algoritmo de Luhn (cartão de crédito) — isso é o que reduz falso positivo
   de ~90% (regex ingênuo) para uma taxa realista de produção.

2. MASCARAMENTO OBRIGATÓRIO — o dado sensível encontrado NUNCA aparece
   completo em nenhum relatório, log, ou prompt de IA. Isso evitaria criar
   um vazamento novo através da própria ferramenta que deveria proteger
   contra vazamento.

3. CONTEXTO REDUZ RUÍDO — valores dentro de arquivos de teste/fixture/mock
   (ex: 'test_cpf.py', diretório 'tests/', 'fixtures/') são sinalizados com
   confiança mais baixa, já que dado de teste sintético é comum e normalmente
   não representa uma pessoa real.
"""

import os
import re


PADROES_ARQUIVOS_TESTE = re.compile(
    r"(test|tests|fixture|fixtures|mock|mocks|spec|specs|__fixtures__|sample|examples?)",
    re.IGNORECASE,
)

EXTENSOES_IGNORADAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".lock",
}

TAMANHO_MAXIMO_ARQUIVO_BYTES = 2 * 1024 * 1024  # 2MB


def _validar_cpf(cpf: str) -> bool:
    cpf = re.sub(r"\D", "", cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    dv1 = (soma * 10 % 11) % 10
    if dv1 != int(cpf[9]):
        return False

    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    dv2 = (soma * 10 % 11) % 10
    return dv2 == int(cpf[10])


def _validar_cnpj(cnpj: str) -> bool:
    cnpj = re.sub(r"\D", "", cnpj)
    if len(cnpj) != 14 or cnpj == cnpj[0] * 14:
        return False

    def _dv(base: str, pesos: list) -> int:
        soma = sum(int(d) * p for d, p in zip(base, pesos))
        resto = soma % 11
        return 0 if resto < 2 else 11 - resto

    pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    dv1 = _dv(cnpj[:12], pesos1)
    if dv1 != int(cnpj[12]):
        return False

    pesos2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    dv2 = _dv(cnpj[:13], pesos2)
    return dv2 == int(cnpj[13])


def _validar_luhn(numero: str) -> bool:
    numero = re.sub(r"\D", "", numero)
    if not (13 <= len(numero) <= 19):
        return False

    soma = 0
    inverso = numero[::-1]
    for i, digito in enumerate(inverso):
        d = int(digito)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        soma += d

    return soma % 10 == 0


def _mascarar(valor: str, manter_inicio: int = 3, manter_fim: int = 2) -> str:
    limpo = re.sub(r"\D", "", valor)
    if len(limpo) <= manter_inicio + manter_fim:
        return "*" * len(limpo)
    meio = "*" * (len(limpo) - manter_inicio - manter_fim)
    return f"{limpo[:manter_inicio]}{meio}{limpo[-manter_fim:]}"


def _mascarar_email(email: str) -> str:
    try:
        usuario, dominio = email.split("@", 1)
    except ValueError:
        return "***"
    if len(usuario) <= 2:
        usuario_mascarado = "*" * len(usuario)
    else:
        usuario_mascarado = usuario[0] + "*" * (len(usuario) - 2) + usuario[-1]
    return f"{usuario_mascarado}@{dominio}"


_REGEX_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_REGEX_CNPJ = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
_REGEX_CARTAO = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _e_arquivo_de_teste(caminho: str) -> bool:
    return bool(PADROES_ARQUIVOS_TESTE.search(caminho))


def _listar_arquivos_texto(caminho_repositorio: str):
    for raiz, dirs, arquivos in os.walk(caminho_repositorio):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", "venv", ".venv")]
        for nome in arquivos:
            _, ext = os.path.splitext(nome)
            if ext.lower() in EXTENSOES_IGNORADAS:
                continue
            caminho_completo = os.path.join(raiz, nome)
            try:
                if os.path.getsize(caminho_completo) > TAMANHO_MAXIMO_ARQUIVO_BYTES:
                    continue
            except OSError:
                continue
            yield caminho_completo


def dlp_scan(caminho_repositorio: str):
    """
    Varre o repositório em busca de CPF, CNPJ, cartão de crédito e e-mail,
    aplicando validação matemática real antes de reportar qualquer achado.

    Retorna uma lista de dicts:
        {
            "tipo": "CPF" | "CNPJ" | "Cartao_Credito" | "Email",
            "arquivo": "caminho/relativo/arquivo.py",
            "linha": 12,
            "valor_mascarado": "123***.***-45",
            "confianca": "alta" | "media",
        }

    Ou "ERRO: <mensagem>" (string) em caso de falha de leitura.
    """
    if not os.path.isdir(caminho_repositorio):
        return f"ERRO: Caminho do repositório inválido: {caminho_repositorio}"

    achados = []

    for caminho_arquivo in _listar_arquivos_texto(caminho_repositorio):
        caminho_relativo = os.path.relpath(caminho_arquivo, caminho_repositorio)
        e_teste = _e_arquivo_de_teste(caminho_relativo)

        try:
            with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
                linhas = f.readlines()
        except Exception:
            continue

        for numero_linha, linha in enumerate(linhas, start=1):

            for match in _REGEX_CPF.finditer(linha):
                if _validar_cpf(match.group()):
                    achados.append({
                        "tipo": "CPF",
                        "arquivo": caminho_relativo,
                        "linha": numero_linha,
                        "valor_mascarado": _mascarar(match.group()),
                        "confianca": "media" if e_teste else "alta",
                    })

            for match in _REGEX_CNPJ.finditer(linha):
                if _validar_cnpj(match.group()):
                    achados.append({
                        "tipo": "CNPJ",
                        "arquivo": caminho_relativo,
                        "linha": numero_linha,
                        "valor_mascarado": _mascarar(match.group()),
                        "confianca": "media" if e_teste else "alta",
                    })

            for match in _REGEX_CARTAO.finditer(linha):
                candidato = match.group()
                digitos = re.sub(r"\D", "", candidato)
                if len(digitos) >= 13 and _validar_luhn(digitos):
                    achados.append({
                        "tipo": "Cartao_Credito",
                        "arquivo": caminho_relativo,
                        "linha": numero_linha,
                        "valor_mascarado": _mascarar(candidato, manter_inicio=4, manter_fim=4),
                        "confianca": "media" if e_teste else "alta",
                    })

            for match in _REGEX_EMAIL.finditer(linha):
                achados.append({
                    "tipo": "Email",
                    "arquivo": caminho_relativo,
                    "linha": numero_linha,
                    "valor_mascarado": _mascarar_email(match.group()),
                    "confianca": "media",
                })

    return achados